import { redis } from './_redis.js';
import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const {
      sender,
      recipient,
      payload
    } = req.body || {};

    if (!sender || !recipient || !payload) {
      return res.status(400).json({
        error: 'sender, recipient and payload required'
      });
    }

    const cleanSender = String(sender).trim();
    const cleanRecipient = String(recipient).trim();

    /*
     * Проверяем, что получатель действительно существует.
     */
    const recipientExists = await redis.exists(
      `user:${cleanRecipient}`
    );

    if (!recipientExists) {
      return res.status(404).json({
        error: 'Получатель не найден'
      });
    }

    /*
     * Проверяем минимальную структуру зашифрованного сообщения.
     */
    if (
      !payload.U ||
      !payload.V ||
      !Array.isArray(payload.nonce) ||
      !Array.isArray(payload.ciphertext)
    ) {
      return res.status(400).json({
        error: 'Некорректный зашифрованный payload'
      });
    }

    const id = crypto.randomUUID();

    const message = {
      id,
      sender: cleanSender,
      recipient: cleanRecipient,
      createdAt: Date.now(),
      payload
    };

    /*
     * Явно сериализуем объект в JSON.
     */
    await redis.rpush(
      `messages:${cleanRecipient}`,
      JSON.stringify(message)
    );

    return res.status(200).json({
      status: 'sent',
      id
    });

  } catch (error) {
    console.error('SEND ERROR:', error);

    return res.status(500).json({
      error: 'Ошибка сервера при отправке сообщения'
    });
  }
}
