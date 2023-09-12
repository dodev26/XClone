import { JwtPayload } from 'jsonwebtoken'
import { UserVerifyStatus } from '~/constants/enum'
import { ParamsDictionary } from 'express-serve-static-core'

export interface RegisterRequestBody {
  email: string
  name: string
  passwordConfirm: string
  password: string
  dateOfBirth: string
}

export interface LoginRequestBody {
  email: string
  password: string
}

export interface LogoutRequestBody {
  refresh_token: string
}

export interface ForgotPasswordRequestBody {
  email: string
}

export interface VerifyForgotPasswordRequestBody {
  forgot_password_token: string
}

export interface ResetPasswordRequestBody {
  password: string
  passwordConfirm: string
  forgot_password_token: string
}

export interface TokenPayload extends JwtPayload {
  userId: string
  tokenType: string
  verify: UserVerifyStatus
}

export interface EmailVerifyRequestBody {
  email_verify_token: string
}

export interface UpdateProfileRequestBody {
  name?: string
  dateOfBirth: string
  bio?: string
  location?: string
  website?: string
  username?: string
  avatar?: string
  cover_photo?: string
}

export interface GetProfileByUsernameRequestParams {
  username: string
}

export interface UnfollowUserRequestParams extends ParamsDictionary {
  userId: string
}

export interface FollowUserRequestBody {
  followed_user_id: string
}

export interface ChangePasswordRequestBody {
  passwordOld: string
  passwordNew: string
  passswordConfirm: string
}
