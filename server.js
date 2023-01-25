import * as dotenv from 'dotenv';
dotenv.config();

import admin from 'firebase-admin';

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import axios, { AxiosHeaders } from 'axios';

import serviceAccount from './firebase.json' assert { type: 'json' };

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const auth = admin.auth();

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(morgan('combined'));

// Auth
app.use(async (req, res, next) => {
  let token = '';
  const basicToken = (req.headers.authorization || '').trim();

  if (basicToken !== '' && basicToken.includes('Basic')) {
    const base64Token = basicToken.split(' ')[1];

    const [email, password] = Buffer.from(base64Token, 'base64')
      .toString()
      .split(':');

    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FB_API_KEY}`;
    const body = { email, password, returnSecureToken: true };

    const res = await axios.post(url, body, {
      headers: new AxiosHeaders().set('Content-Type', 'application/json'),
    });

    token = res.data.idToken;
  } else {
    token = (req.header('X-Token-Api') || '').trim();
  }

  if (token !== '') {
    try {
      const decodedToken = await auth.verifyIdToken(token);
      req.user = await auth.getUser(decodedToken.uid);

      return next();
    } catch (_) {}
  }

  res.status(401).end('Unauthorized');
});

app.get('/api/data', async (req, res) => {
  const userId = req.user?.uid ?? '';

  if (userId.trim() !== '') {
    try {
      const result = await db.collection(`accounts/${userId}/data`).get();
      const docs = result.docs.map(x => x.data());

      return res.status(200).json(docs);
    } catch (error) {
      console.error(error);
      return res.status(500).json(error);
    }
  }

  res.status(422).end();
});

app.post('/api/data', async (req, res) => {
  const userId = req.user?.uid ?? '';

  if (userId.trim() !== '') {
    try {
      const valid = req.body.reading >= 0 && req.body.reading <= 14;
      await db
        .collection(`accounts/${userId}/data`)
        .add({ ...req.body, valid });
      return res.status(201).end();
    } catch (error) {
      console.error(error);
      return res.status(500).json(error);
    }
  }

  res.status(200).end();
});

app.all('*', (req, res) => res.status(404).end());

app.listen(port, () => console.info(`App listening on port ${port}...`));
