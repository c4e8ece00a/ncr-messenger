import crypto from 'node:crypto';

import {
  getRedis
} from '../lib/redis.js';

import {
  sendPush
} from '../lib/push.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  requireSameOrigin,
  jsonBodySize,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

const MAX_PAYLOAD_SIZE =
  60000;

function validDeviceId(value) {
  return (
    typeof value === 'string' &&
    /^[0-9a-f-]{36}$/i.test(value)
  );
}

export default async function handler(
  req,
  res
) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({
      error:
        'Method not allowed'
    });
  }

  if (
    !requireSameOrigin(
      req,
      res
    )
  ) {
    return;
  }

  if (
    jsonBodySize(req) >
    64 * 1024
  ) {
    return res.status(413).json({
      error:
        'Сообщение слишком большое'
    });
  }

  try {
    const redis =
      getRedis();

    const session =
      await requireSession(
        req,
        res,
        redis
      );

    if (!session) return;

    const recipient =
      normalizeUsername(
        req.body?.recipient
      );

    const encrypted =
      req.body?.encrypted;

    if (
      !validUsername(
        recipient
      )
    ) {
      return res.status(400).json({
        error:
          'Некорректный получатель'
      });
    }

    if (
      !Array.isArray(
        encrypted
      ) ||
      encrypted.length === 0
    ) {
      return res.status(400).json({
        error:
          'Нет зашифрованных копий сообщения'
      });
    }

    if (
      encrypted.length > 50
    ) {
      return res.status(400).json({
        error:
          'Слишком много устройств'
      });
    }

    const userExists =
      await redis.exists(
        `user:${recipient}`
      );

    if (!userExists) {
      return res.status(404).json({
        error:
          'Получатель не найден'
      });
    }

    const messageId =
      crypto.randomUUID();

    const createdAt =
      Date.now();

    let stored = 0;
    let pushSent = 0;

    const uniqueDevices =
      new Set();

    for (
      const item of encrypted
    ) {
      if (
        !item ||
        typeof item !== 'object'
      ) {
        continue;
      }

      const deviceId =
        item.deviceId;

      const payload =
        item.payload;

      if (
        !validDeviceId(
          deviceId
        )
      ) {
        continue;
      }

      if (
        uniqueDevices.has(
          deviceId
        )
      ) {
        continue;
      }

      uniqueDevices.add(
        deviceId
      );

      if (
        !payload ||
        typeof payload !== 'object' ||
        !payload.U ||
        !payload.V ||
        !payload.nonce ||
        !payload.ciphertext
      ) {
        continue;
      }

      const payloadSize =
        JSON.stringify(
          payload
        ).length;

      if (
        payloadSize >
        MAX_PAYLOAD_SIZE
      ) {
        continue;
      }

      const deviceRaw =
        await redis.get(
          `device:${recipient}:${deviceId}`
        );

      if (!deviceRaw) {
        continue;
      }

      let device;

      try {
        device =
          typeof deviceRaw ===
            'string'
            ? JSON.parse(deviceRaw)
            : deviceRaw;
      } catch {
        continue;
      }

      if (
        device?.username !==
        recipient
      ) {
        continue;
      }

      const message = {
        id: messageId,

        sender:
          session.username,

        recipient,

        recipientDeviceId:
          deviceId,

        createdAt,

        U: payload.U,
        V: payload.V,
        nonce:
          payload.nonce,
        ciphertext:
          payload.ciphertext
      };

      await redis.rpush(
        `messages:${recipient}`,
        JSON.stringify(message)
      );

      stored++;

      /*
       * Push ищем именно по аккаунту,
       * а затем проверяем deviceId.
       */
      const pushKeys =
        await redis.keys(
          `push:${recipient}:*`
        );

      for (
        const pushKey of pushKeys
      ) {
        try {
          const raw =
            await redis.get(
              pushKey
            );

          if (!raw) continue;

          const subscription =
            typeof raw === 'string'
              ? JSON.parse(raw)
              : raw;

          if (
            subscription?.deviceId !==
            deviceId
          ) {
            continue;
          }

          await sendPush(
            subscription.subscription,
            {
              type:
                'new-message',

              sender:
                session.username,

              messageId,

              url: '/'
            }
          );

          pushSent++;
        } catch (pushError) {
          console.error(
            'Push delivery failed:',
            pushError?.statusCode ||
              pushError?.message ||
              pushError
          );

          if (
            pushError?.statusCode ===
              404 ||
            pushError?.statusCode ===
              410
          ) {
            await redis.del(
              pushKey
            );
          }
        }
      }
    }

    if (stored === 0) {
      return res.status(400).json({
        error:
          'Ни одно устройство получателя не зарегистрировано'
      });
    }

    return res.status(200).json({
      status: 'sent',
      id: messageId,
      devices: stored,
      pushSent
    });
  } catch (error) {
    console.error(
      'POST /api/send:',
      error?.message ||
        error
    );

    return res.status(500).json({
      error:
        'Ошибка отправки'
    });
  }
}