import webpush from 'web-push';

let configured = false;

function configure() {
  if (configured) return;

  const publicKey =
    process.env.VAPID_PUBLIC_KEY;

  const privateKey =
    process.env.VAPID_PRIVATE_KEY;

  const subject =
    process.env.VAPID_SUBJECT;

  if (
    !publicKey ||
    !privateKey ||
    !subject
  ) {
    throw new Error(
      'VAPID is not configured'
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
  const publicKey =
    process.env.VAPID_PUBLIC_KEY;

  if (!publicKey) {
    throw new Error(
      'VAPID_PUBLIC_KEY is not configured'
    );
  }

  return publicKey;
}

export async function sendPush(
  subscription,
  payload
) {
  configure();

  return webpush.sendNotification(
    subscription,
    JSON.stringify(payload),
    {
      TTL: 60,
      urgency: 'high'
    }
  );
}