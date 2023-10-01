import express from 'express';
import {
  userListGet,
  //check,
  checkToken,
  userDelete,
  userGet,
  userPost,
  userPut,
} from '../controllers/userController';
import {authenticate} from '../../middlewares';

const router = express.Router();

router
  .route('/')
  .post(userPost)
  .get(userListGet)
  .put(authenticate, userPut)
  .delete(authenticate, userDelete);

router.get('/token', authenticate, checkToken);

//router.route('/check').get(check);

router.route('/:id').get(userGet);

export default router;
