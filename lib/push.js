import webpush from 'web-push';
import { sha256 } from './security.js';

let configured = false;

function configurePush() {
  if (configured) return;

  const publicKey = process.env.VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT;

  if (!publicKey || !privateKey || !subject) {
    throw new Error(
      'Web Push is not configured. Set VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and VAPID_SUBJECT.'
    );
  }

  webpush.setVapidDetails(
    subject,
    publicKey,
    privateKey
  );

  configured = true;
}

export function getVapidPublicKey() {
  const publicKey = process.env.VAPID_PUBLIC_KEY;

  if (!publicKey) {
    throw new Error('VAPID_PUBLIC_KEY is not configured');
  }

  return publicKey;
}

export function validateSubscription(subscription) {
  if (!subscription || typeof subscription !== 'object') {
    return false;
  }

  if (typeof subscription.endpoint !== 'string') {
    return false;
  }

  if (subscription.endpoint.length < 20 || subscription.endpoint.length > 4096) {
    return false;
  }

  try {
    const url = new URL(subscription.endpoint);

    if (url.protocol !== 'https:') {
      return false;
    }
  } catch {
    return false;
  }

  if (!subscription.keys || typeof subscription.keys !== 'object') {
    return false;
  }

  if (
    typeof subscription.keys.p256dh !== 'string' ||
    typeof subscription.keys.auth !== 'string'
  ) {
    return false;
  }

  if (
    subscription.keys.p256dh.length < 20 ||
    subscription.keys.p256dh.length > 512
  ) {
    return false;
  }

  if (
    subscription.keys.auth.length < 10 ||
    subscription.keys.auth.length > 256
  ) {
    return false;
  }

  return true;
}

export function subscriptionId(subscription) {
  return sha256(subscription.endpoint);
}

export async function sendPush(subscription, payload) {
  configurePush();

  return webpush.sendNotification(
    subscription,
    JSON.stringify(payload),
    {
      TTL: 60,
      urgency: 'high'
    }
  );
}