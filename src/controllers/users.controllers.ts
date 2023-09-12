import { NextFunction, Request, Response } from 'express'
import usersServices from '~/services/users.services'
import { ParamsDictionary } from 'express-serve-static-core'
import {
  ChangePasswordRequestBody,
  EmailVerifyRequestBody,
  FollowUserRequestBody,
  ForgotPasswordRequestBody,
  GetProfileByUsernameRequestParams,
  LoginRequestBody,
  LogoutRequestBody,
  RegisterRequestBody,
  ResetPasswordRequestBody,
  TokenPayload,
  UnfollowUserRequestParams,
  UpdateProfileRequestBody,
  VerifyForgotPasswordRequestBody
} from '~/models/requests/User.requests'
import { ObjectId } from 'mongodb'
import User from '~/models/schemas/User.schema'
import { USER_MESSAGES } from '~/constants/messages'
import { HttpStatusCode, UserVerifyStatus } from '~/constants/enum'
import databaseService from '~/services/database.services'
import { config } from 'dotenv'
config()

export const registerController = async (
  req: Request<ParamsDictionary, any, RegisterRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const payload = req.body

  const result = await usersServices.Register(payload)
  return res.status(HttpStatusCode.Created).json({
    message: USER_MESSAGES.REGISTER_SUCCESSFULLY,
    result: {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    }
  })
}

export const loginController = async (req: Request<ParamsDictionary, any, LoginRequestBody>, res: Response) => {
  const user = req.user as User
  const userId = user._id as ObjectId
  // await databaseService.RefeshTokens.deleteMany({ userId })
  const result = await usersServices.Login({
    userId: userId.toString(),
    verify: user.verify
  })
  return res.status(HttpStatusCode.Ok).json({
    message: USER_MESSAGES.LOGIN_SUCCESSFULLY,
    result
  })
}

export const oauthController = async (req: Request, res: Response, next: NextFunction) => {
  const { code } = req.query

  const result = await usersServices.oauth(code as string)
  const { accessToken, newUser, refreshToken, verify } = result
  const urlRedirect = `${process.env.CLIENT_REDIRECT_CALLBACK}?access_token=${accessToken}&refresh_token=${refreshToken}&new_user=${newUser}&verify=${verify}`
  return res.redirect(urlRedirect)
}
export const LogoutController = async (req: Request<ParamsDictionary, any, LogoutRequestBody>, res: Response) => {
  const { refresh_token } = req.body
  const result = await usersServices.Logout(refresh_token)
  return res.status(HttpStatusCode.Ok).json(result)
}

export const emailVerifyController = async (
  req: Request<ParamsDictionary, any, EmailVerifyRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.decoded_email_verify_token as TokenPayload
  const user = await databaseService.users.findOne({ _id: new ObjectId(userId) })
  if (!user) {
    return res.status(HttpStatusCode.NotFound).json({
      message: USER_MESSAGES.USER_NOT_FOUND
    })
  }
  if (user.email_verify_token === '') {
    return res.status(HttpStatusCode.Ok).json({
      message: USER_MESSAGES.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }
  const result = await usersServices.verifyEmail(userId)
  return res.json({
    message: USER_MESSAGES.EMAIL_VERIFY_SUCCESSFULLY,
    result
  })
}

export const resendVerifyEmailController = async (req: Request, res: Response, next: NextFunction) => {
  const { userId } = req.decoded_authorization as TokenPayload
  const user = await databaseService.users.findOne({ _id: new ObjectId(userId) })
  if (!user) {
    return res.status(HttpStatusCode.NotFound).json({
      message: USER_MESSAGES.USER_NOT_FOUND
    })
  }
  if (user.verify === UserVerifyStatus.Verified) {
    return res.status(HttpStatusCode.Ok).json({
      message: USER_MESSAGES.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }
  const result = await usersServices.resendVerifyEmail(userId)
  return res.status(HttpStatusCode.Ok).json(result)
}

export const forgotPasswordController = async (
  req: Request<ParamsDictionary, any, ForgotPasswordRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const { _id, verify } = req.user as User
  const result = await usersServices.forgotPassword({
    userId: _id.toString(),
    verify
  })
  return res.json(result)
}

export const verifyForgotPasswordController = async (
  req: Request<ParamsDictionary, any, VerifyForgotPasswordRequestBody>,
  res: Response,
  next: NextFunction
) => {
  return res.json({
    message: USER_MESSAGES.VERIFY_FORGOT_PASSWORD_SUCCESSFULLY
  })
}

export const resetPasswordController = async (
  req: Request<ParamsDictionary, any, ResetPasswordRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.decoded_forgot_password_verify_token as TokenPayload
  const { password } = req.body
  const result = await usersServices.resetPassword(userId, password)
  return res.json(result)
}

export const getProfileController = async (req: Request, res: Response, next: NextFunction) => {
  const { userId } = req.decoded_authorization as TokenPayload
  const result = await usersServices.getProfile(userId)
  return res.json({
    message: USER_MESSAGES.GET_PROFILE_SUCCESSFULLY,
    result
  })
}

export const updateProfileController = async (
  req: Request<ParamsDictionary, any, UpdateProfileRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.decoded_authorization as TokenPayload
  const { body: payload } = req
  const result = await usersServices.updateProfile(userId, payload)
  return res.json({
    message: USER_MESSAGES.UPDATE_PROFILE_SUCCESSFULLY,
    result
  })
}

export const getProfileByUsernameController = async (
  req: Request<GetProfileByUsernameRequestParams>,
  res: Response,
  next: NextFunction
) => {
  const { username } = req.params
  console.log(username)
  const result = await usersServices.getProfileByUsername(username)
  return res.json({
    message: USER_MESSAGES.GET_PROFILE_SUCCESSFULLY,
    result
  })
}

export const followController = async (
  req: Request<ParamsDictionary, any, FollowUserRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.decoded_authorization as TokenPayload
  const { followed_user_id } = req.body
  const result = await usersServices.follow(userId, followed_user_id)
  return res.json(result)
}

export const unfollowController = async (
  req: Request<UnfollowUserRequestParams>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.decoded_authorization as TokenPayload
  const { userId: user_id_u_followed } = req.params
  const result = await usersServices.unfollow(userId, user_id_u_followed)
  return res.json(result)
}

export const changPasswordController = async (
  req: Request<ParamsDictionary, any, ChangePasswordRequestBody>,
  res: Response,
  next: NextFunction
) => {
  const { userId } = req.decoded_authorization as TokenPayload
  const { passwordNew } = req.body
  const result = await usersServices.changePassword(userId, passwordNew)
  return res.json(result)
}
