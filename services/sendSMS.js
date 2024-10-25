const twilio = require('twilio');
require('dotenv').config();
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
// FPUGLWNV9KCLS2A94V6N1KS6
const client = twilio(accountSid, authToken);

async function sendSms(to, body) {
    try {
        const message = await client.messages.create({
            body,
            to,
            from: '9600449077', 
        });
        console.log('SMS sent:', message.sid);
        return message.sid;
    } catch (error) {
        console.error('Error sending SMS:', error);
        throw error;
    }
}

module.exports = { sendSms };