import crypto from 'node:crypto';

import { getRedis } from '../lib/redis.js';
import { sendPush } from '../lib/push.js';

import {
  securityHeaders,
  noStore,
  requireSession,
  requireSameOrigin,
  jsonBodySize,
  normalizeUsername,
  validUsername
} from '../lib/security.js';

const MAX_PAYLOAD_SIZE = 60000;

function getErrorStatus(error) {
  return (
    error?.statusCode ||
    error?.status ||
    null
  );
}

export default async function handler(req, res) {
  securityHeaders(res);
  noStore(res);

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  if (!requireSameOrigin(req, res)) {
    return;
  }

  if (jsonBodySize(req) > 64 * 1024) {
    return res.status(413).json({
      error: 'Сообщение слишком большое'
    });
  }

  try {
    const redis = getRedis();

    const session =
      await requireSession(
        req,
        res,
        redis
      );

    if (!session) {
      return;
    }

    const recipient =
      normalizeUsername(
        req.body?.recipient
      );

    const payload =
      req.body?.payload;

    if (!validUsername(recipient)) {
      return res.status(400).json({
        error: 'Некорректный получатель'
      });
    }

    if (
      !payload ||
      typeof payload !== 'object'
    ) {
      return res.status(400).json({
        error:
          'Некорректный encrypted payload'
      });
    }

    if (
      !payload.U ||
      !payload.V ||
      !payload.nonce ||
      !payload.ciphertext
    ) {
      return res.status(400).json({
        error:
          'Повреждённый encrypted payload'
      });
    }

    const payloadSize =
      JSON.stringify(payload).length;

    if (
      payloadSize >
      MAX_PAYLOAD_SIZE
    ) {
      return res.status(413).json({
        error:
          'Encrypted payload слишком большой'
      });
    }

    /*
     * Проверяем существование аккаунта.
     *
     * Это единственное, что необходимо
     * для доставки сообщения.
     */
    const recipientExists =
      await redis.exists(
        `user:${recipient}`
      );

    if (!recipientExists) {
      return res.status(404).json({
        error:
          'Получатель не найден'
      });
    }

    /*
     * Создаём сообщение.
     *
     * Оно уже полностью зашифровано
     * на клиенте.
     */
    const message = {
      id: crypto.randomUUID(),

      sender:
        session.username,

      recipient,

      createdAt:
        Date.now(),

      ...payload
    };

    /*
     * ГЛАВНОЕ:
     *
     * Сообщение сохраняется независимо
     * от Push.
     */
    await redis.rpush(
      `messages:${recipient}`,
      JSON.stringify(message)
    );

    /*
     * Push — только уведомление.
     *
     * Если Push отсутствует,
     * сообщение всё равно считается
     * успешно доставленным в очередь.
     */
    const pushPayload = {
      type: 'new-message',

      sender:
        session.username,

      messageId:
        message.id
    };

    const subscriptions =
      await redis.keys(
        `push:${recipient}:*`
      );

    let pushSent = 0;
    let pushRemoved = 0;

    /*
     * Если у пользователя нет
     * ни одного устройства с Push —
     * это НЕ ошибка.
     */
    if (
      Array.isArray(subscriptions) &&
      subscriptions.length > 0
    ) {
      for (
        const key of subscriptions
      ) {
        try {
          const raw =
            await redis.get(key);

          if (!raw) {
            continue;
          }

          const stored =
            typeof raw === 'string'
              ? JSON.parse(raw)
              : raw;

          const subscription =
            stored?.subscription;

          if (
            !subscription ||
            typeof subscription !== 'object'
          ) {
            await redis.del(key);
            pushRemoved++;
            continue;
          }

          await sendPush(
            subscription,
            pushPayload
          );

          pushSent++;
        } catch (pushError) {
          const status =
            getErrorStatus(
              pushError
            );

          console.error(
            'Push delivery failed:',
            status ||
              pushError?.message ||
              pushError
          );

          /*
           * 404 / 410:
           * Push-подписка больше
           * не существует.
           *
           * Удаляем только её.
           */
          if (
            status === 404 ||
            status === 410
          ) {
            try {
              await redis.del(key);
              pushRemoved++;
            } catch (deleteError) {
              console.error(
                'Failed to remove dead push subscription:',
                deleteError?.message ||
                  deleteError
              );
            }
          }

          /*
           * Остальные Push-ошибки
           * НЕ отменяют доставку сообщения.
           */
        }
      }
    }

    /*
     * Сообщение сохранено.
     *
     * Поэтому всегда возвращаем success,
     * даже если Push не был отправлен.
     */
    return res.status(200).json({
      status: 'sent',

      id:
        message.id,

      pushSent,

      pushRemoved,

      devices:
        Array.isArray(subscriptions)
          ? subscriptions.length
          : 0
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