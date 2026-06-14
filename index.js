const axios = require("axios");
const winston = require('winston');
const hyperDX = require("@hyperdx/node-logger");
const AWS = require("aws-sdk");
const sqs = new AWS.SQS({ region: "eu-north-1" });
const redis = require('redis');
const { v4: uuidv4 } = require("uuid");

//ENV
const GRAPHQL_API_URL = process.env.HASURA_GRAPHQL_ENDPOINT;
const MAX_ACCOUNT_CREATIONS = process.env.MAX_ACCOUNT_CREATIONS;
const ACCOUNT_WINDOW_SECONDS = process.env.ACCOUNT_WINDOW_SECONDS;
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = process.env.REDIS_PORT;
const CACHE_TTL_SECONDS = parseInt(process.env.CACHE_TTL_SECONDS || "604800", 10);
const SQS_QUEUE_URL = process.env.SQS_CAPTCHA_SUBMISSION_QUEUE_URL;

// ============ Session Management Helpers ============
let _redisClient;
async function getRedisClient() {
  if (_redisClient && _redisClient.isOpen) return _redisClient;
  _redisClient = redis.createClient({ url: `redis://${REDIS_HOST}:${REDIS_PORT}` });
  _redisClient.on("error", (e) => console.error("Redis error:", e));
  await _redisClient.connect();
  return _redisClient;
}

async function getSessionMetadata(sessionId) {
  const key = `session:metadata:${sessionId}`;
  try {
    const r = await getRedisClient();
    const v = await r.get(key);
    return v ? JSON.parse(v) : { lastShownInstructionId: null, attemptCount: 0, failedAttempts: 0, isMFARequired: false, mfaSolvedAt: null };
  } catch (error) {
    console.error("Error getting session metadata:", error);
    return { lastShownInstructionId: null, attemptCount: 0, failedAttempts: 0, isMFARequired: false, mfaSolvedAt: null };
  }
}

async function updateSessionMetadata(sessionId, metadata) {
  const key = `session:metadata:${sessionId}`;
  try {
    const r = await getRedisClient();
    await r.set(key, JSON.stringify(metadata), { EX: CACHE_TTL_SECONDS });
  } catch (error) {
    console.error("Error updating session metadata:", error);
  }
}

async function updateSubmissionAttempt(sessionId, instructionId, submissionStatus, mfaEnabled = false) {
  const metadata = await getSessionMetadata(sessionId);
  metadata.lastSubmissionTime = new Date().toISOString();
  metadata.lastSubmissionStatus = submissionStatus;
  metadata.lastSubmittedInstructionId = instructionId;
  
  if (submissionStatus === 'failed') {
    metadata.failedAttempts = (metadata.failedAttempts || 0) + 1;
    if (metadata.failedAttempts >= 3) {
      metadata.isMFARequired = true;
    }
  } else if (submissionStatus === 'success') {
    metadata.failedAttempts = 0;
    if (mfaEnabled || metadata.isMFARequired) {
      metadata.isMFARequired = true;
    } else {
      metadata.isMFARequired = false;
    }
  }
  
  await updateSessionMetadata(sessionId, metadata);
}

function isMFAEnabledInConfig(mfaConfig) {
  if (!mfaConfig || !Array.isArray(mfaConfig) || mfaConfig.length === 0) {
    return false;
  }
  return mfaConfig.some(item => {
    return item.all === true || item.login_only === true || item.via_email === true;
  });
}

function timeToSeconds(timeString) {
  const timeComponents = timeString.split(' ');
  let hours = 0, minutes = 0, seconds = 0;
  for (let i = 0; i < timeComponents.length; i += 2) {
    const value = parseInt(timeComponents[i]);
    const unit = timeComponents[i + 1].toLowerCase();
    if (unit.includes('hour')) hours = value;
    else if (unit.includes('minute')) minutes = value;
    else if (unit.includes('second')) seconds = value;
  }
  return hours * 3600 + minutes * 60 + seconds;
}

function checkIsFraud(condition) {
  if (condition.solvedBeforeVisible || condition.solvingTime < 2 || 
      condition.isHeadlessBrowser || condition.isOldBrowser) {
    return true;
  }
  return false;
}

function calculateBotScore(condition) {
  let score = 0;
  if (condition.lang !== "en-US" || !condition.lang.includes("es")) score += 1;
  if (condition.deviceType == "mobile") score += 1;
  if (condition.location.countryCode !== "US") score += 1;
  if (condition.currentHour >= 1 && condition.currentHour < 5) score += 1;
  if (condition.isOldBrowser) score += 1;
  if (condition.isHeadlessBrowser) score += 1;
  if (condition.solvedBeforeVisible) score += 1;
  if (condition.solvingTime < 2) score += 1;
  if (!condition.hasExtensionsOrPlugins) score += 1;
  return score;
}

async function getLocationDetails(ip_address) {
  try {
    const url = `https://freeipapi.com/api/json/${ip_address}`;
    const response = await axios.get(url);
    return response.data;
  } catch (error) {
    console.log(error);
    return false;
  }
}

async function getDataFromRedis(key) {
  const client = await redis.createClient({
    url: `redis://${REDIS_HOST}:${REDIS_PORT}`
  }).on('error', err => console.log('Redis Client Error', err)).connect();
  
  const response = await client.get(key);
  await client.quit();
  return response && response != null ? JSON.parse(response) : null;
}

async function checkDeviceAssociation(email, visitorId, headers, logger) {
  const result = {
    isAssociated: false,
    isNewDevice: true
  };
  
  if (!email || !visitorId) {
    return result;
  }
  
  try {
    // Use Hasura aggregate queries to get counts (bounded response)
    const query = {
      query: `query($email: String!, $visitorId: String!) {
        associatedCount: bb_captcha_submissions_aggregate(where: {
          email: {_eq: $email},
          device_status: {_eq: "associated"},
          visitor_id: {_eq: $visitorId}
        }) {
          aggregate { count }
        }
        totalCount: bb_captcha_submissions_aggregate(where: {
          email: {_eq: $email},
          visitor_id: {_eq: $visitorId}
        }) {
          aggregate { count }
        }
      }`,
      variables: { email: email, visitorId: visitorId }
    };

    const response = await axios.post(GRAPHQL_API_URL, query, { headers });
    const data = response.data?.data;

    if (data) {
      const assocCount = data.associatedCount?.aggregate?.count || 0;
      const totCount = data.totalCount?.aggregate?.count || 0;

      if (assocCount > 0) {
        result.isAssociated = true;
        logger.info(`Device association verified: visitorId ${visitorId} is associated with email ${email}`);
      }

      if (totCount > 0) {
        result.isNewDevice = false;
        logger.info(`Device is not new: previous submission(s) found for visitorId ${visitorId}`);
      } else {
        logger.info(`Device is new: no previous submissions found for visitorId ${visitorId}`);
      }
    }
  } catch (err) {
    logger.error("Error checking device association: " + err.message);
  }
  
  return result;
}

async function incrementAccountCreation(key) {
  const client = await redis.createClient({
    url: `redis://${REDIS_HOST}:${REDIS_PORT}`
  }).on('error', err => console.log('Redis Error', err)).connect();

  let count = await client.get(key);
  if (!count) {
    await client.set(key, 1, { EX: ACCOUNT_WINDOW_SECONDS });
    count = 1;
  } else {
    count = await client.incr(key);
  }
  await client.quit();
  return Number(count);
}

async function checkAccountCreationLimit({ domainURL, ip }) {
  const baseKey = `qc:acct:${domainURL}`;
  if (ip) {
    const ipKey = `${baseKey}:ip:${ip}`;
    const ipCount = await incrementAccountCreation(ipKey);
    if (ipCount > MAX_ACCOUNT_CREATIONS) {
      return true;
    }
  }
  return false;
}

function isPointInPolygon(x, y, polygon, selectedArrowInfo) {
  console.log('selectedArrowInfo ===', selectedArrowInfo)

  // Flatten the polygon array if it is passed in as a nested array [[...]]
  if (polygon && Array.isArray(polygon[0]) && !('x' in polygon[0])) {
      polygon = polygon[0];
  }

  // If x is an array, we are validating/solving a full trace
  if (Array.isArray(x)) {
      const trace = x;
      if (trace.length === 0 || !polygon || polygon.length === 0) {
          return false;
      }

      let pointsInside = 0;
      let firstInside = null;
      let lastInside = null;
      const filteredInsidePoints = [];

      // Re-use standard point-in-polygon check for each point in the trace
      for (const point of trace) {
          if (isPointInPolygon(point.x, point.y, polygon, selectedArrowInfo)) {
              pointsInside++;
              filteredInsidePoints.push(point);
              if (!firstInside) firstInside = point;
              lastInside = point;
          }
      }

      let overlapDistance = 0;
      if (firstInside && lastInside) {
          overlapDistance = Math.hypot(lastInside.x - firstInside.x, lastInside.y - firstInside.y);
      }

      let directionCorrect = true;

      if (filteredInsidePoints.length > 1 && selectedArrowInfo) {
          const startPt = filteredInsidePoints[0];
          const endPt = filteredInsidePoints[filteredInsidePoints.length - 1];

          const traceDx = endPt.x - startPt.x;
          const traceDy = endPt.y - startPt.y;
          const traceLength = Math.hypot(traceDx, traceDy);

          const expectedDx = Math.cos(selectedArrowInfo.rotation);
          const expectedDy = Math.sin(selectedArrowInfo.rotation);

          const traceUnitDx = traceDx / (traceLength || 1);
          const traceUnitDy = traceDy / (traceLength || 1);

          // Raw directional tracking vector
          const dotProductUnit = traceUnitDx * expectedDx + traceUnitDy * expectedDy;

          // FIX: Wrap in Math.abs() to permit backward strokes along the exact same path
          if (Math.abs(dotProductUnit) < 0.866) {
              directionCorrect = false;
          } else {
              let parallelSegments = 0;
              let totalSegments = 0;
              const step = Math.max(1, Math.floor(filteredInsidePoints.length / 5));

              for (let i = 0; i < filteredInsidePoints.length - step; i += step) {
                  const pt1 = filteredInsidePoints[i];
                  const pt2 = filteredInsidePoints[i + step];
                  const dx = pt2.x - pt1.x;
                  const dy = pt2.y - pt1.y;
                  const len = Math.hypot(dx, dy);
                  if (len > 2) {
                      const segmentDot = (dx / len) * expectedDx + (dy / len) * expectedDy;

                      // FIX: Wrap in Math.abs() so sub-segments moving in reverse pass grid checks
                      if (Math.abs(segmentDot) >= 0.75) {
                          parallelSegments++;
                      }
                      totalSegments++;
                  }
              }
              if (totalSegments > 0 && (parallelSegments / totalSegments) < 0.6) {
                  directionCorrect = false;
              }
          }
      } else {
          directionCorrect = false;
      }

      const hasSufficientOverlap = pointsInside > 0 && (overlapDistance >= 15 || pointsInside > 3);
      const isSuccess = hasSufficientOverlap && directionCorrect;
      console.log('isSuccess === ', isSuccess)

      return isSuccess;
  }

  // Standard point-in-polygon logic
  let inside = false;
  const n = polygon.length;

  for (let i = 0, j = n - 1; i < n; j = i++) {
      const xi = polygon[i].x,
          yi = polygon[i].y;
      const xj = polygon[j].x,
          yj = polygon[j].y;

      const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;

      if (intersect) inside = !inside;
  }
  console.log('inside ===', inside)
  return inside;
}

function isPointInAnyPolygon(x, y, correctGrid) {
  if (!Array.isArray(correctGrid)) return false;
  return correctGrid.some(polygon => isPointInPolygon(x, y, polygon));
}

function validateTrace(trace, correctGrid, selectedArrowInfo) {
  const pointsToValidate = trace;
  if (pointsToValidate.length === 0 || correctGrid.length === 0 || correctGrid[0].length === 0) {
    return false;
  }
  const polygon = correctGrid[0];
  let pointsInside = 0;
  for (const point of pointsToValidate) {
    if (isPointInPolygon(point.x, point.y, polygon, selectedArrowInfo)) {
      pointsInside++;
    }
  }
  console.log('pointsInside', pointsInside);
  console.log('pointsToValidate === ', pointsToValidate.length);
  const coverage = (pointsInside / pointsToValidate.length) * 100;
  const threshold = 50;
  return coverage >= threshold;
}

async function sendToSQS(submissionData, logger) {
  try {
    const params = {
      QueueUrl: SQS_QUEUE_URL,
      MessageBody: JSON.stringify(submissionData),
      DelaySeconds: 5
    };
    
    const response = await sqs.sendMessage(params).promise();
    logger.info(`Message queued to SQS: ${response.MessageId}`);
    return response.MessageId;
  } catch (error) {
    logger.error(`Failed to send message to SQS: ${error.message}`);
    throw error;
  }
}

function getInstructionByIdAndIndex(data, instructionId, index) {
  if (!data || !data.bb_instructions) return null;
  const group = data.bb_instructions.find(group => group.id === instructionId);
  if (!group || !Array.isArray(group.instructions)) return null;
  return group.instructions.find(inst => inst.index === index) || null;
}

exports.handler = async (event, context) => {
  const headers = {
    "x-hasura-admin-secret": process.env.HASURA_ADMIN_SECRET,
    "content-type": "application/json",
  };
  const response_headers = {
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST",
    "Access-Control-Allow-Crendentials": "true",
  };
  
  const MAX_LEVEL = 'info';
  const hyperdxTransport = new hyperDX.HyperDXWinston({
    apiKey: process.env.HYPERDX_API_KEY,
    maxLevel: 'info',
    service: 'captcha-submit-api',
  });

  const logger = winston.createLogger({
    level: MAX_LEVEL,
    service: 'captcha-submit-api',
    format: winston.format.json(),
    transports: [
      new winston.transports.Console(),
      hyperdxTransport,
    ],
  });
  
  try {
    const { captchaId, userId, email, submissionDetails, isNewDevice, isAssociated, associated_device_details, timeElapsed, timeToSolve, pageOpenedAt, userAgent, deviceType, browserVersion, os, location, language, isHeadlessBrowser, isOldBrowser, hasExtensionsOrPlugins, url, isBot, botDetails, domainURL, mfa, captcha_type, session_id } = JSON.parse(event.body);
    let insertSchema = {};
    let attempt = false;
    
    // Extract visitorId early for device association tracking
    const incomingVisitorId = associated_device_details?.components?.visitorId || associated_device_details?.visitorId || null;
    
    // VALIDATE SESSION_ID
    if (!session_id) {
      logger.warn("Session ID not provided in request");
    } else {
      try {
        const sessionMetadata = await getSessionMetadata(session_id);
        if (sessionMetadata && sessionMetadata.initiatedBy) {
          const requestUserEmail = email?.toLowerCase();
          if (requestUserEmail !== sessionMetadata.initiatedBy) {
            logger.error(`USER ISOLATION VIOLATION: User ${requestUserEmail} tried to submit using session created by ${sessionMetadata.initiatedBy}`);
            return {
              headers: response_headers,
              statusCode: 403,
              body: JSON.stringify({
                statusCode: 403,
                message: "Unauthorized: Session does not belong to this user.",
                error: true,
                code: "USER_ISOLATION_VIOLATION"
              }),
            };
          }
          logger.info(`User isolation verified: ${requestUserEmail} owns session ${session_id}`);
        }
      } catch (isolationError) {
        logger.warn(`Failed to verify user isolation for session ${session_id}: ${isolationError.message}`);
      }
    }
    
    if (!userAgent) {
      logger.error("Failed to submit Quick Check");
      return {
        headers: response_headers,
        body: JSON.stringify({
          statusCode: 400,
          message: "User agent is empty",
          error: true,
        }),
      };
    }

    const sourceIp = event.requestContext.identity.sourceIp;
    logger.info(`Fetching location details from IP Address: ${sourceIp}`);
    const locationFromCache = await getDataFromRedis(`userlocation-${sourceIp}`);
    let locationDetails;
    
    if (!locationFromCache) {
      const startTime = Date.now();
      locationDetails = await getLocationDetails(sourceIp);
      const endTime = Date.now();
      logger.info(`Fetched location details successfully in ${endTime - startTime}ms`);
      await new Promise(resolve => setTimeout(resolve, 100)); // Allow Redis to be ready
    } else {
      locationDetails = locationFromCache;
    }

    // Defensive check: if locationDetails is false or invalid, use defaults
    if (!locationDetails || typeof locationDetails !== 'object') {
      locationDetails = { countryCode: 'UNKNOWN', regionName: '', cityName: '', timeZone: '', latitude: 0, longitude: 0 };
    }

    const country = locationDetails.countryCode;
    const stateName = locationDetails?.regionName;
    const cityName = locationDetails?.cityName;
    const timezoneName = locationDetails?.timeZone;
    const latitude = locationDetails?.latitude;
    const longitude = locationDetails?.longitude;

    // RETRIEVE CACHED PACKAGE
    let redisData = null;
    if (email) {
      const userSpecificCacheKey = `${captchaId}:user:${email.toLowerCase()}`;
      redisData = await getDataFromRedis(userSpecificCacheKey);
      if (redisData) {
        logger.info(`Retrieved package from user-specific key for email: ${email.toLowerCase()}`);
      }
    }
    
    if (!redisData) {
      redisData = await getDataFromRedis(captchaId);
      if (redisData) {
        logger.info(`Retrieved package from base key (fallback): ${captchaId}`);
      }
    }
    
    if (!redisData) {
      logger.error("Failed to submit Quick Check as Redis Key has been expired");
      return {
        headers: response_headers,
        body: JSON.stringify({
          statusCode: 422,
          message: "Captcha timeout! Please try again.",
          error: true,
        }),
      };
    }

    // VERIFY PACKAGE OWNERSHIP
    if (redisData?.config?.initiatedBy) {
      const packageInitiator = redisData.config.initiatedBy;
      const requestUserEmail = email?.toLowerCase();
      if (requestUserEmail !== packageInitiator) {
        logger.error(`SECURITY VIOLATION: User ${requestUserEmail} attempted to submit package initiated by ${packageInitiator}`);
        return {
          headers: response_headers,
          statusCode: 403,
          body: JSON.stringify({
            statusCode: 403,
            message: "Unauthorized: This captcha package belongs to a different user.",
            error: true,
            code: "PACKAGE_OWNERSHIP_VIOLATION"
          }),
        };
      }
      logger.info(`Package ownership verified: ${requestUserEmail} owns the captcha package`);
    }

    // BUILD INSERT SCHEMA
    if (typeof captchaId !== "undefined") {
      insertSchema.captcha_id = redisData?.quickCheckId;
    }
    if (typeof userId !== "undefined" && typeof userId == "number") {
      insertSchema.user_id = userId;
    }
    if (typeof email !== "undefined" && email !== "") {
      insertSchema.email = email;
    }
    if (redisData?.config?.email_anonymized === true) {
      insertSchema.email = "anonymous";
    }
    if (typeof location !== "undefined" && location) {
      insertSchema.location = location;
    }
    if (typeof submissionDetails !== "undefined" && submissionDetails) {
      insertSchema.submission_details = submissionDetails;
    }
    // --- Device Association Logic ---
    const deviceAssociationResult = await checkDeviceAssociation(email, incomingVisitorId, headers, logger);
    insertSchema.associated_device = deviceAssociationResult.isAssociated;
    insertSchema.new_device = deviceAssociationResult.isNewDevice;
    if (typeof timeElapsed !== "undefined" && timeElapsed !== "") {
      insertSchema.time_elapsed = timeElapsed;
    }
    if(typeof timeToSolve !=="undefined" && timeToSolve !==""){
      insertSchema.time_to_solve = timeToSolve
    }
    if (typeof pageOpenedAt !== "undefined" && pageOpenedAt !== "") {
      insertSchema.page_opening_time = pageOpenedAt;
    }
    if (typeof userAgent !== "undefined" && userAgent !== "") {
      insertSchema.submission_user_agent = userAgent;
    }
    if (typeof deviceType !== "undefined" && deviceType !== "") {
      insertSchema.device_type = deviceType;
    }
    if (typeof browserVersion !== "undefined" && browserVersion !== "") {
      insertSchema.version = browserVersion;
    }
    if (typeof country !== "undefined" && country !== "") {
      insertSchema.country = country;
    }
    if (typeof os !== "undefined") {
      insertSchema.os = os;
    }
    if (typeof sourceIp !== "undefined") {
      insertSchema.ip_address = sourceIp;
    }
    if (typeof isBot !== "undefined") {
      insertSchema.isBot = isBot;
    }
    if (typeof botDetails !== "undefined") {
      insertSchema.botDetails = botDetails;
    }
    if (typeof associated_device_details !== "undefined") {
      insertSchema.associated_device_details = associated_device_details;
    }
    if (incomingVisitorId) {
      insertSchema.visitor_id = incomingVisitorId;
    }
    if (typeof domainURL !== "undefined") {
      insertSchema.domainURL = domainURL;
    }
    if (typeof session_id !== "undefined") {
      insertSchema.session_id = session_id;
    }
    
    insertSchema.state = stateName || '';
    insertSchema.city = cityName || '';
    insertSchema.defaultTimezone = timezoneName || '';
    if (!location?.lat) {
      insertSchema.location = { "lat": latitude, "lng": longitude };
    }

    // BOT DETECTION
    let bot_score = redisData?.bot_score || 0;
    const date = new Date();
    const currentHour = date.getHours();
    const solvingTime = timeToSeconds(timeElapsed);
    let solvedBeforeVisible = false;
    if (solvingTime < 2) solvedBeforeVisible = true;
    
    const conditions = {
      lang: language,
      deviceType: deviceType,
      location: { countryCode: country },
      currentHour: currentHour,
      solvingTime: solvingTime,
      solvedBeforeVisible: solvedBeforeVisible,
      isOldBrowser: isOldBrowser,
      isHeadlessBrowser: isHeadlessBrowser,
      isNewDevice: isNewDevice,
      isAssociated: isAssociated
    };
    
    logger.info(`Calculating Bot Score from condition: ${JSON.stringify(conditions)}`);
    let calculatedScore = calculateBotScore(conditions);
    let isFraud = checkIsFraud(conditions);
    logger.info(`checked isFraud conditions: ${JSON.stringify(conditions)}`);

    // GET INSTRUCTION
    const instructionsObj = getInstructionByIdAndIndex(redisData, submissionDetails.instructionId, submissionDetails?.index);
    if (!instructionsObj) {
      return {
        headers: response_headers,
        body: JSON.stringify({
          statusCode: 400,
          message: "Invalid property values in submissionDetails",
          error: true,
        }),
      };
    }

    // VALIDATE CAPTCHA SOLUTION
    if (captcha_type === 'ARROW_DEFAULT') {
      console.log('Solving ARROW Captcha');
      if (!validateTrace(submissionDetails.userSelectedGrid, instructionsObj.correctGrid, instructionsObj?.selectedArrowInfo)) {
        calculatedScore += 1;
        attempt = false;
        insertSchema.blockReason = 'action';
      } else {
        attempt = true;
        if (calculatedScore != 0) {
          calculatedScore -= 1;
        }
      }
    } else {
      console.log('Solving SKIN Captcha');
      if (!isPointInAnyPolygon(submissionDetails.userSelectedGrid?.x, submissionDetails.userSelectedGrid?.y, instructionsObj.correctGrid)) {
        calculatedScore += 1;
        attempt = false;
        insertSchema.blockReason = 'action';
      } else {
        attempt = true;
        if (calculatedScore != 0) {
          calculatedScore -= 1;
        }
      }
    }

    // FRAUD POTENTIAL
    let fraudPotential, fraudPotentialSeverity;
    if (calculatedScore >= 0 && calculatedScore <= 4) {
      fraudPotential = 3;
      fraudPotentialSeverity = 'low';
    } else if (calculatedScore > 4 && calculatedScore <= 7) {
      fraudPotential = 2;
      fraudPotentialSeverity = 'medium';
    } else if (calculatedScore > 7 && calculatedScore <= 10) {
      fraudPotential = 1;
      fraudPotentialSeverity = 'high';
    }
    
    insertSchema.fraudPotential = fraudPotential;
    insertSchema.attempt_status = attempt;
    insertSchema.bot_score = calculatedScore;
    insertSchema.isFraud = isFraud;
    insertSchema.subtype_id = redisData?.config?.submission_type_id;
    insertSchema.companyid = redisData?.company_id;
    insertSchema.skin_id = redisData?.config?.skin_id;

    // ACCOUNT CREATION LIMIT CHECK
    let isBlocked = false;
    if (redisData?.config?.submission_type === "account creation") {
      isBlocked = await checkAccountCreationLimit({
        domainURL,
        ip: sourceIp
      });
      
      if (isBlocked) {
        logger.warn("Blocked by excessive account creation");
        insertSchema.blockReason = "Blocked By Excessive Account Creation";
        insertSchema.attempt_status = false;
      }
    }

    // **KEY CHANGE: Generate submissionId BEFORE sending to SQS**
    // NOTE: UUID for tracking only, NOT for database primary key
    const submissionId = uuidv4();
    insertSchema.submission_tracking_id = submissionId; // Store UUID in separate column
    // DO NOT set insertSchema.id - let database auto-generate the bigint ID
    insertSchema.created_at = new Date().toISOString();

    // ADD SQS-SPECIFIC METADATA
    const sqsMessage = {
      postedData: insertSchema,
      quickCheckId: redisData?.captcha_uid,
      bot_score: calculatedScore + bot_score,
      submissionId: submissionId,
      email: email,
      domainURL: domainURL,
      isFraud: isFraud,
      attempt: attempt,
      url: url,
      session_id: session_id,
      visitorId: incomingVisitorId, // Include for SQS worker processing
      redisConfig: redisData?.config, // Pass config for email handling in worker
      fraudPotentialSeverity: fraudPotentialSeverity,
      isNewDevice: isNewDevice,
      isBlocked: isBlocked
    };

    // SEND TO SQS (INSTEAD OF SAVING DIRECTLY)
    try {
      await sendToSQS(sqsMessage, logger);
      logger.info(`Submission queued to SQS with submissionId: ${submissionId}`);
    } catch (sqsError) {
      logger.error(`Failed to queue submission to SQS: ${sqsError.message}`);
      return {
        headers: response_headers,
        statusCode: 500,
        body: JSON.stringify({
          statusCode: 500,
          message: "Failed to process submission",
          error: true,
        }),
      };
    }

    // CHECK IF MFA IS ENABLED (DEFINED ONCE FOR USE IN BOTH SUCCESS AND FAILURE PATHS)
    const isMFAEnabledForUser = isMFAEnabledInConfig(redisData?.config?.mfa);

    // UPDATE SESSION METADATA FOR TRACKING
    if (!attempt) {
      logger.error(`Quick check was not solved. Please try again.`);
      
      if (session_id && submissionDetails?.instructionId) {
        await updateSubmissionAttempt(session_id, submissionDetails?.instructionId, 'failed', isMFAEnabledForUser);
        const metadata = await getSessionMetadata(session_id);
        logger.info(`Session ${session_id} now has ${metadata.failedAttempts} failed attempts`);
        
        let failResponse = {
          statusCode: 200,
          message: "Invalid Captcha",
          isBlocked,
          success: false,
          session_id: session_id,
          isMFA: metadata.isMFARequired || isMFAEnabledForUser,
          failedAttempts: metadata.failedAttempts,
          submission_id: submissionId,
          submission_tracking_id: submissionId
        };
        
        // NEW LOGIC: Show MFA if 3+ consecutive failed attempts (regardless of config)
        if (metadata.failedAttempts >= 3) {
          failResponse.isMFA = true;
          logger.info(`MFA Required due to 3+ consecutive failed attempts: ${metadata.failedAttempts}`);
        } else {
          logger.info(`Failed attempt (${metadata.failedAttempts}/3). MFA not yet triggered.`);
        }
        
        return {
          headers: response_headers,
          body: JSON.stringify(failResponse),
        };
      }
    }

    // UPDATE SESSION FOR SUCCESSFUL SUBMISSION
    let finalMetadata = null;
    if (session_id && submissionDetails?.instructionId) {
      await updateSubmissionAttempt(session_id, submissionDetails?.instructionId, 'success', isMFAEnabledForUser);
      finalMetadata = await getSessionMetadata(session_id);
      logger.info(`Updated session metadata for successful submission: ${session_id}`);
    }

    logger.info("Quick Check has been Submitted Successfully");

    let successResponse = {
      statusCode: 200,
      message: "Captcha has been submitted successfully.",
      submission_id: submissionId,
      submission_tracking_id: submissionId,
      isBlocked,
      success: true,
      session_id: session_id,
      isMFA: false,
      failedAttempts: finalMetadata?.failedAttempts ?? 0
    };
    
    // NEW LOGIC: Show MFA on each successful submission if MFA is enabled in config or still required by session state
    if (isMFAEnabledForUser || finalMetadata?.isMFARequired) {
      successResponse.isMFA = true;
      logger.info(`MFA Required on successful submission (config=${isMFAEnabledForUser}, sessionMFA=${finalMetadata?.isMFARequired})`);
    } else {
      logger.info(`MFA not enabled in config, submission complete without MFA`);
    }

    return {
      headers: response_headers,
      body: JSON.stringify(successResponse),
    };
  } catch (error) {
    console.log("error while solving Quick check === ", error);
    logger.error("Failed to submit Quick Check");
    return { 
      headers: response_headers,
      body: JSON.stringify({
        statusCode: 500,
        message: error.message,
        error: true,
      }),
    };
  }
};
