const admin = require('firebase-admin');
const serviceAccount = require('./firebaseSMSKey.json'); 

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    // databaseURL: "https://ultron-b2d6c.firebaseio.com"
});

