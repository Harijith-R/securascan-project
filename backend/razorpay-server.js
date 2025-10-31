const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');
const cors = require('cors'); // Import cors

// --- CONFIGURATION ---
// These should be set in your deployment environment (Vercel, Cloudflare), not hardcoded.
const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
const razorpayWebhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
const appId = process.env.APP_ID || 'securascan-prod';

// --- INITIALIZATION ---
let db;
try {
    const serviceAccount = JSON.parse(serviceAccountKey);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    db = admin.firestore();
} catch (error) {
    console.error("Firebase Admin initialization failed:", error);
}

const app = express();

// --- MIDDLEWARE ---

// Enable CORS for all routes
// This is important if you ever want your frontend to call this backend directly.
app.use(cors()); 

// Use express.json() for all routes. 
// For Razorpay webhooks, we need the raw body, so we define it separately.
app.use((req, res, next) => {
  if (req.path === '/razorpay-webhook') {
    // Use express.raw() for the webhook endpoint
    express.raw({ type: 'application/json' })(req, res, next);
  } else {
    // Use express.json() for all other routes
    express.json()(req, res, next);
  }
});

// --- ROUTES ---
app.get('/', (req, res) => {
  res.send('SecuraScan Backend Server is running.');
});

/**
 * Razorpay Webhook Endpoint
 * This listens for the `payment_link.paid` event.
 */
app.post('/razorpay-webhook', async (req, res) => {
  const signature = req.headers['x-razorpay-signature'];
  
  if (!razorpayWebhookSecret) {
      console.error('RAZORPAY_WEBHOOK_SECRET is not set.');
      return res.status(500).send('Internal server configuration error.');
  }

  if (!signature) {
    return res.status(400).send('Missing Razorpay signature');
  }

  // 1. Verify the webhook signature
  try {
    const shasum = crypto.createHmac('sha256', razorpayWebhookSecret);
    shasum.update(req.body); // Use the raw body
    const digest = shasum.digest('hex');

    if (digest !== signature) {
      console.warn('Invalid webhook signature');
      return res.status(400).send('Invalid signature');
    }
  } catch (error) {
    console.error('Error verifying webhook signature:', error);
    return res.status(500).send('Signature verification failed');
  }

  // 2. Process the event
  let event;
  try {
      // Manually parse the raw body to JSON *after* verification
      event = JSON.parse(req.body.toString());
  } catch (error) {
      console.error('Error parsing webhook JSON:', error);
      return res.status(400).send('Invalid JSON payload');
  }

  if (event.event === 'payment_link.paid') {
    const paymentLink = event.payload.payment_link.entity;
    
    // Retrieve the user_id and plan from the 'notes' field
    // IMPORTANT: You MUST set these notes (`user_id` and `plan`) 
    // when creating the payment link in your Razorpay dashboard.
    const userId = paymentLink.notes?.user_id;
    const plan = paymentLink.notes?.plan; // e.g., "Pro"

    if (!userId || !plan) {
      console.error('Webhook payload missing user_id or plan in notes.', paymentLink.notes);
      // Send 200 OK so Razorpay stops retrying
      return res.status(200).send('Payload processed but missing required notes.');
    }
    
    if(!db) {
        console.error('Firestore (db) is not initialized. Cannot process webhook.');
        return res.status(500).send('Internal server error: DB not connected.');
    }

    // 3. Update the user's document in Firestore
    try {
      const userDocRef = db.collection(`artifacts/${appId}/users`).doc(userId);
      const userDoc = await userDocRef.get();

      if (!userDoc.exists) {
        console.error(`User document not found for user_id: ${userId}`);
        return res.status(200).send('User not found, but webhook acknowledged.');
      }

      // Define plan details
      const planDetails = {
        'Starter': { scansRemaining: 25, subscription: 'starter' },
        'Pro': { scansRemaining: 50, subscription: 'pro' },
        'Business': { scansRemaining: -1, subscription: 'business' } // -1 for unlimited
      };

      const newPlan = planDetails[plan];

      if (!newPlan) {
        console.error(`Invalid plan name received: ${plan}`);
        return res.status(200).send('Invalid plan name, but webhook acknowledged.');
      }

      // Update Firestore
      await userDocRef.update({
        subscription: newPlan.subscription,
        scansRemaining: newPlan.scansRemaining
      });

      console.log(`Successfully upgraded user ${userId} to ${plan} plan.`);
      
      // Send 200 OK to Razorpay
      res.status(200).send('Webhook processed successfully.');

    } catch (error) {
      console.error('Error updating Firestore:', error);
      // Send 500 to indicate an internal error. Razorpay might retry.
      res.status(500).send('Error updating user data.');
    }
  } else {
    // Not the event we're looking for, but acknowledge it
    res.status(200).send('Event received but not processed.');
  }
});

// --- START SERVER ---
// This is for local development. Vercel will handle this automatically.
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 8080;
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
}

// Export the app for serverless environments like Vercel
module.exports = app;

