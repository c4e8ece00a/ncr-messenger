import { redis } from './_redis.js';
import crypto from 'crypto';

function hashPassword(password) {
  return crypto
    .createHash('sha256')
    .update(password)
    .digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const {
      username,
      password,
      publicKey
    } = req.body || {};

    if (!username || !password || !publicKey) {
      return res.status(400).json({
        error: 'username, password and publicKey required'
      });
    }

    const cleanUsername = String(username).trim();

    if (cleanUsername.length < 2 || cleanUsername.length > 32) {
      return res.status(400).json({
        error: 'Имя должно содержать от 2 до 32 символов'
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        error: 'Пароль должен содержать минимум 4 символа'
      });
    }

    const userKey = `user:${cleanUsername}`;
    const publicKeyKey = `publicKey:${cleanUsername}`;

    const passwordHash = hashPassword(password);

    const existingUser = await redis.get(userKey);

    /*
     * Существующий пользователь
     */
    if (existingUser) {
      if (existingUser.passwordHash !== passwordHash) {
        return res.status(401).json({
          error: 'Неверный пароль'
        });
      }

      /*
       * КРИТИЧЕСКИ ВАЖНО:
       *
       * Старый код каждый раз заменял publicKey.
       * Из-за этого можно было получить ситуацию:
       *
       * отправитель -> новый publicKey
       * получатель -> старый privateKey
       *
       * Расшифровка невозможна.
       *
       * Теперь публичный ключ существующего пользователя
       * не заменяется.
       */
      if (existingUser.publicKey !== publicKey) {
        return res.status(409).json({
          error:
            'Для этого аккаунта уже существует другой ключ шифрования. ' +
            'Очистка данных браузера или вход с другого устройства ' +
            'не может восстановить старый приватный ключ.'
        });
      }

      return res.status(200).json({
        status: 'logged_in',
        username: cleanUsername,
        publicKey: existingUser.publicKey
      });
    }

    /*
     * Новый пользователь
     */
    const user = {
      passwordHash,
      publicKey
    };

    await redis.set(userKey, user);
    await redis.set(publicKeyKey, publicKey);

    return res.status(200).json({
      status: 'registered',
      username: cleanUsername,
      publicKey
    });

  } catch (error) {
    console.error('AUTH ERROR:', error);

    return res.status(500).json({
      error: 'Ошибка сервера при авторизации'
    });
  }
}
