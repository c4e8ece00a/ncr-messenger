import webpush from 'web-push';

let configured = false;

function configurePush() {
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

export async function sendPush(
  subscription,
  payload
) {
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
