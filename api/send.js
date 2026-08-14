import { kv } from '@vercel/kv';
import webpush from 'web-push';

// Замените на свои VAPID ключи (как сгенерировать – ниже)
const VAPID_PUBLIC_KEY = 'BMr8YsMDhvdx8Yvw60pR6sCVl20kecplpbTu8eXldRvHF_NXNP_prEcSmtt95TnK-foo9voDA1ig8ufv_eT3v_s';
const VAPID_PRIVATE_KEY = 'UopTjfsLDOo0h_8nq-aQrTTQFHYrzlWsg7s74HTUevI';
const VAPID_SUBJECT = 'mailto: <bendind@rambler.ru>';

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { recipient, payload } = req.body;
  if (!recipient || !payload) return res.status(400).json({ error: 'recipient and payload required' });

  // Сохраняем сообщение
  await kv.rpush(`messages:${recipient}`, JSON.stringify(payload));

  // Отправляем push-уведомление, если есть подписка
  const subStr = await kv.get(`subscription:${recipient}`);
  if (subStr) {
    try {
      const subscription = JSON.parse(subStr);
      await webpush.sendNotification(subscription, JSON.stringify({
        title: 'Новое сообщение',
        body: 'Вам пришло зашифрованное сообщение',
      }));
    } catch (e) {
      console.error('Push failed', e);
    }
  }

  return res.status(200).json({ status: 'sent' });
}
