// /smarthome endpoint - Google Smart Home fulfillment
const express = require('express');
const router = express.Router();

// In-memory storage (replace with database in production)
const deviceStates = new Map();
const userDevices = new Map();

// Initialize sample devices for demo user
function initializeSampleDevices(userId) {
  if (!userDevices.has(userId)) {
    userDevices.set(userId, [
      {
        id: 'plug-living-01',
        type: 'action.devices.types.OUTLET',
        traits: ['action.devices.traits.OnOff', 'action.devices.traits.EnergyStorage'],
        name: {
          name: 'Living Room Plug',
          nicknames: ['tv plug', 'living room outlet']
        },
        willReportState: true,
        deviceInfo: {
          manufacturer: 'DarkSmart',
          model: 'DS-Plug-1',
          hwVersion: '1.0',
          swVersion: '2.1.0'
        },
        attributes: {
          queryOnlyEnergyStorage: false
        }
      },
      {
        id: 'light-bedroom-01',
        type: 'action.devices.types.LIGHT',
        traits: [
          'action.devices.traits.OnOff',
          'action.devices.traits.Brightness',
          'action.devices.traits.ColorSetting'
        ],
        name: {
          name: 'Bedroom Light',
          nicknames: ['bedroom lamp', 'main light']
        },
        willReportState: true,
        deviceInfo: {
          manufacturer: 'DarkSmart',
          model: 'DS-Light-RGB',
          hwVersion: '2.0',
          swVersion: '3.0.1'
        },
        attributes: {
          colorModel: 'rgb',
          colorTemperatureRange: {
            temperatureMinK: 2000,
            temperatureMaxK: 6500
          }
        }
      },
      {
        id: 'thermostat-main-01',
        type: 'action.devices.types.THERMOSTAT',
        traits: [
          'action.devices.traits.TemperatureSetting'
        ],
        name: {
          name: 'Main Thermostat',
          nicknames: ['thermostat', 'main temp']
        },
        willReportState: true,
        deviceInfo: {
          manufacturer: 'DarkSmart',
          model: 'DS-Thermo-Pro',
          hwVersion: '1.5',
          swVersion: '4.2.0'
        },
        attributes: {
          availableThermostatModes: ['off', 'heat', 'cool', 'auto'],
          thermostatTemperatureUnit: 'C'
        }
      },
      {
        id: 'lock-front-01',
        type: 'action.devices.types.LOCK',
        traits: ['action.devices.traits.LockUnlock'],
        name: {
          name: 'Front Door Lock',
          nicknames: ['front lock', 'main door']
        },
        willReportState: true,
        deviceInfo: {
          manufacturer: 'DarkSmart',
          model: 'DS-Lock-Secure',
          hwVersion: '1.0',
          swVersion: '1.5.2'
        }
      }
    ]);

    // Initialize device states
    deviceStates.set('plug-living-01', { on: false, online: true });
    deviceStates.set('light-bedroom-01', {
      on: false,
      brightness: 100,
      color: { spectrumRgb: 16777215 },
      online: true
    });
    deviceStates.set('thermostat-main-01', {
      thermostatMode: 'heat',
      thermostatTemperatureSetpoint: 20,
      thermostatTemperatureAmbient: 18,
      online: true
    });
    deviceStates.set('lock-front-01', {
      isLocked: true,
      isJammed: false,
      online: true
    });
  }
}

// Middleware to validate bearer token
// Replace the existing validateToken function with this:
function validateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Missing or invalid authorization header'
    });
  }

  const token = authHeader.substring(7);
  
  // Import JWT from parent (add at top of file if not there)
  const jwt = require('jsonwebtoken');
  const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
  
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.sub;
    
    // Initialize sample devices for this user
    initializeSampleDevices(req.userId);
    
    next();
  } catch (err) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
  }
}

// Handle SYNC intent - return all devices for user
function handleSync(userId, requestId) {
  const devices = userDevices.get(userId) || [];
  
  return {
    requestId: requestId,
    payload: {
      agentUserId: userId, // Changed from `darksmart-${userId}` to match token
      devices: devices
    }
  };
}

// Handle QUERY intent - return current state for requested devices
function handleQuery(userId, requestId, devices = []) {
  const responseDevices = {};

  // Normalize input: Google sends an array of device objects with "id" keys
  const deviceIds = Array.isArray(devices)
    ? devices.map(d => d.id || d.ids).flat().filter(Boolean)
    : [];

  deviceIds.forEach(deviceId => {
    const state = deviceStates.get(deviceId);
    if (state) {
      responseDevices[deviceId] = state;
    } else {
      responseDevices[deviceId] = {
        online: false,
        errorCode: 'deviceNotFound'
      };
    }
  });

  return {
    requestId,
    payload: {
      devices: responseDevices
    }
  };
}


// Handle EXECUTE intent - execute commands on devices
function handleExecute(userId, requestId, commands) {
  const commandResults = [];

  commands.forEach(command => {
    const deviceIds = command.devices.map(d => d.id);
    const execution = command.execution[0];
    
    const results = [];
    
    deviceIds.forEach(deviceId => {
      const currentState = deviceStates.get(deviceId);
      
      if (!currentState) {
        results.push({
          ids: [deviceId],
          status: 'ERROR',
          errorCode: 'deviceNotFound'
        });
        return;
      }

      if (!currentState.online) {
        results.push({
          ids: [deviceId],
          status: 'ERROR',
          errorCode: 'deviceOffline'
        });
        return;
      }

      // Execute the command and update state
      let newState = { ...currentState };
      let success = true;
      let errorCode = null;

      try {
        switch (execution.command) {
          case 'action.devices.commands.OnOff':
            newState.on = execution.params.on;
            break;

          case 'action.devices.commands.BrightnessAbsolute':
            newState.brightness = execution.params.brightness;
            break;

          case 'action.devices.commands.ColorAbsolute':
            if (execution.params.color.spectrumRGB !== undefined) {
              newState.color = { spectrumRgb: execution.params.color.spectrumRGB };
            } else if (execution.params.color.temperature !== undefined) {
              newState.color = { temperatureK: execution.params.color.temperature };
            }
            break;

          case 'action.devices.commands.ThermostatTemperatureSetpoint':
            newState.thermostatTemperatureSetpoint = execution.params.thermostatTemperatureSetpoint;
            break;

          case 'action.devices.commands.ThermostatSetMode':
            newState.thermostatMode = execution.params.thermostatMode;
            break;

          case 'action.devices.commands.LockUnlock':
            newState.isLocked = execution.params.lock;
            newState.isJammed = false;
            break;

          default:
            success = false;
            errorCode = 'functionNotSupported';
        }

        if (success) {
          // Update stored state
          deviceStates.set(deviceId, newState);
          
          results.push({
            ids: [deviceId],
            status: 'SUCCESS',
            states: newState
          });

          // TODO: Send command to actual physical device here
          // await sendToPhysicalDevice(deviceId, execution.command, execution.params);
          
          // TODO: If willReportState is true, call reportStateAndNotification API
          // await reportStateToGoogle(userId, deviceId, newState);
        } else {
          results.push({
            ids: [deviceId],
            status: 'ERROR',
            errorCode: errorCode
          });
        }
      } catch (error) {
        results.push({
          ids: [deviceId],
          status: 'ERROR',
          errorCode: 'hardError',
          debugString: error.message
        });
      }
    });

    commandResults.push(...results);
  });

  return {
    requestId: requestId,
    payload: {
      commands: commandResults
    }
  };
}

// Handle DISCONNECT intent - user unlinked account
function handleDisconnect(userId, requestId) {
  // Clean up user data
  userDevices.delete(userId);
  
  // Clean up device states for this user's devices
  const devices = userDevices.get(userId) || [];
  devices.forEach(device => {
    deviceStates.delete(device.id);
  });

  // TODO: Revoke all tokens for this user
  // TODO: Call HomeGraph.deleteAgentUser API
  // const { google } = require('googleapis');
  // const homegraph = google.homegraph('v1');
  // await homegraph.devices.deleteAgentUser({
  //   requestBody: {
  //     agentUserId: `darksmart-${userId}`
  //   }
  // });

  return {
    requestId: requestId,
    payload: {}
  };
}

// Main fulfillment endpoint
router.post('/', validateToken, (req, res) => {
  try {
    const { requestId, inputs } = req.body;
    
    if (!requestId || !inputs || !inputs[0]) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing requestId or inputs'
      });
    }

    const intent = inputs[0].intent;
    const userId = req.userId;

    let response;

    switch (intent) {
      case 'action.devices.SYNC':
        response = handleSync(userId, requestId);
        break;

      case 'action.devices.QUERY':
        response = handleQuery(userId, requestId, inputs[0].payload.devices);
        break;

      case 'action.devices.EXECUTE':
        response = handleExecute(userId, requestId, inputs[0].payload.commands);
        break;

      case 'action.devices.DISCONNECT':
        response = handleDisconnect(userId, requestId);
        break;

      default:
        return res.status(400).json({
          error: 'invalid_intent',
          error_description: `Unsupported intent: ${intent}`
        });
    }

    res.json(response);
  } catch (error) {
    console.error('Fulfillment error:', error);
    res.status(500).json({
      requestId: req.body?.requestId || 'error',
      payload: {
        errorCode: 'hardError',
        debugString: error.message
      }
    });
  }
});

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'smarthome-fulfillment' });
});

module.exports = router;