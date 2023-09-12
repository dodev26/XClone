import express from 'express'
import {
  LogoutController,
  changPasswordController,
  emailVerifyController,
  followController,
  forgotPasswordController,
  getProfileByUsernameController,
  getProfileController,
  loginController,
  oauthController,
  registerController,
  resendVerifyEmailController,
  resetPasswordController,
  unfollowController,
  updateProfileController,
  verifyForgotPasswordController
} from '~/controllers/users.controllers'
import {
  accessTokenValidator,
  changePasswordValidator,
  emailVerifyValidator,
  followValidator,
  forgotPasswordValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator,
  resetPasswordValidator,
  unfollowValidator,
  updateProfileValidator,
  verifiedUserValidator,
  verifyForgotPasswordTokenValidator
} from '~/middlewares/users.middlewares'
import { query, validationResult } from 'express-validator'
import { wrapRequestHandler } from '~/utils/handlers'
import { filterMiddleware } from '~/middlewares/common.middlewares'
import { UpdateProfileRequestBody } from '~/models/requests/User.requests'

const usersRouter = express.Router()

usersRouter.get('/users', query('name').notEmpty().withMessage('name is required').escape(), (req: any, res: any) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array()
    })
  }
  res.send(req.query.name)
})
usersRouter.post('/register', registerValidator, wrapRequestHandler(registerController))

usersRouter.post('/login', loginValidator, wrapRequestHandler(loginController))

usersRouter.get('/oauth/google', wrapRequestHandler(oauthController))

usersRouter.post('/logout', accessTokenValidator, refreshTokenValidator, wrapRequestHandler(LogoutController))

usersRouter.post('/verify-email', emailVerifyValidator, wrapRequestHandler(emailVerifyController))

usersRouter.post('/resend-verify-email', accessTokenValidator, wrapRequestHandler(resendVerifyEmailController))

usersRouter.post('/forgot-password', forgotPasswordValidator, wrapRequestHandler(forgotPasswordController))

usersRouter.post(
  '/verify-forgot-password',
  verifyForgotPasswordTokenValidator,
  wrapRequestHandler(verifyForgotPasswordController)
)

usersRouter.post('/reset-password', resetPasswordValidator, wrapRequestHandler(resetPasswordController))

usersRouter.get('/profile', accessTokenValidator, wrapRequestHandler(getProfileController))

usersRouter.patch(
  '/update-profile',
  accessTokenValidator,
  verifiedUserValidator,
  updateProfileValidator,
  filterMiddleware<UpdateProfileRequestBody>([
    'avatar',
    'bio',
    'cover_photo',
    'dateOfBirth',
    'location',
    'name',
    'username',
    'website'
  ]),
  wrapRequestHandler(updateProfileController)
)

usersRouter.get('/:username', wrapRequestHandler(getProfileByUsernameController))

usersRouter.post(
  '/follow',
  accessTokenValidator,
  verifiedUserValidator,
  followValidator,
  wrapRequestHandler(followController)
)

usersRouter.delete(
  '/follow/:userId',
  accessTokenValidator,
  verifiedUserValidator,
  unfollowValidator,
  wrapRequestHandler(unfollowController)
)

usersRouter.put(
  '/change-password',
  accessTokenValidator,
  verifiedUserValidator,
  changePasswordValidator,
  wrapRequestHandler(changPasswordController)
)
export default usersRouter
