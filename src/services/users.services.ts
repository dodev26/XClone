import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { RegisterRequestBody, UpdateProfileRequestBody } from '~/models/requests/User.requests'
import { hashPassword } from '~/utils/crypto'
import { signToken } from '~/utils/jwt'
import { HttpStatusCode, TokenType, UserVerifyStatus } from '~/constants/enum'
import RefreshToken from '~/models/schemas/RefreshToken.schema'
import { ObjectId } from 'mongodb'
import { config } from 'dotenv'
import { USER_MESSAGES } from '~/constants/messages'
import { ErrorWithStatus } from '~/models/Errors'
import Follower from '~/models/schemas/Follower.schema'
import axios from 'axios'
import { generateRandomPassword } from '~/utils/scripts'
config()
class UsersServices {
  private async signAccessToken({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: { userId, token_type: TokenType.AccessToken, verify },
      privateKey: process.env.JWT_SECRET_ACCESS_TOKEN as string,
      options: {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN
      }
    })
  }
  private async signRefreshToken({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: { userId, token_type: TokenType.RefreshToken, verify },
      privateKey: process.env.JWT_SECRET_REFRESH_TOKEN as string,
      options: {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN
      }
    })
  }
  private async signEmailVerifyToken({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: { userId, token_type: TokenType.EmailVerificationToken, verify },
      privateKey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN as string,
      options: {
        expiresIn: process.env.EMAIL_VERIFY_TOKEN_EXPIRES_IN
      }
    })
  }
  private async signForgotPasswordToken({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: { userId, token_type: TokenType.ForgotPasswordToken, verify },
      privateKey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN as string,
      options: {
        expiresIn: process.env.FORGOT_PASSWORD_TOKEN_EXPIRES_IN
      }
    })
  }
  private signAccessTokenAndRefreshToken({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    return Promise.all([this.signAccessToken({ userId, verify }), this.signRefreshToken({ userId, verify })])
  }

  private async getGoogleUserInfo(access_token: string, id_token: string) {
    const res = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
      params: {
        access_token,
        alt: 'json'
      },
      headers: {
        Authorization: `Bearer ${id_token}`
      }
    })
    return res.data as {
      id: string
      email: string
      verified_email: boolean
      name: string
      given_name: string
      family_name: string
      picture: string
      locale: string
    }
  }
  private async getOAuthGoogleToken(code: string) {
    const body = {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
      access_type: 'offline'
    }

    const res = await axios.post('https://oauth2.googleapis.com/token', body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    return res.data as {
      id_token: string
      access_token: string
    }
  }
  async Register(payload: RegisterRequestBody) {
    const userId = new ObjectId()
    const email_verify_token = await this.signEmailVerifyToken({
      userId: userId.toString(),
      verify: UserVerifyStatus.Unverified
    })
    await databaseService.users.insertOne(
      new User({
        ...payload,
        _id: userId,
        username: `user${userId.toString()}`,
        email_verify_token,
        dateOfBirth: new Date(payload.dateOfBirth),
        password: hashPassword(payload.password)
      })
    )

    const [accessToken, refreshToken] = await this.signAccessTokenAndRefreshToken({
      userId: userId.toString(),
      verify: UserVerifyStatus.Unverified
    })
    await databaseService.RefeshTokens.insertOne(
      new RefreshToken({ userId: new ObjectId(userId), token: refreshToken })
    )
    console.log('email_verify_token', email_verify_token)
    return {
      accessToken,
      refreshToken
    }
  }
  async CheckEmailExist(email: string) {
    const user = await databaseService.users.findOne({ email })
    return Boolean(user)
  }
  async Login({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    const [accessToken, refreshToken] = await this.signAccessTokenAndRefreshToken({
      userId,
      verify
    })
    await databaseService.RefeshTokens.insertOne(
      new RefreshToken({ userId: new ObjectId(userId), token: refreshToken })
    )
    return {
      accessToken,
      refreshToken
    }
  }

  async oauth(code: string) {
    const { access_token, id_token } = await this.getOAuthGoogleToken(code)
    const userInfo = await this.getGoogleUserInfo(access_token, id_token)
    if (!userInfo.verified_email) {
      throw new ErrorWithStatus({
        message: USER_MESSAGES.GMAIL_NOT_VERIFIED,
        status: HttpStatusCode.BadRequest
      })
    }
    const user = await databaseService.users.findOne({ email: userInfo.email })
    if (user) {
      const [accessToken, refreshToken] = await this.signAccessTokenAndRefreshToken({
        userId: user._id.toString(),
        verify: user.verify
      })
      await databaseService.RefeshTokens.insertOne(
        new RefreshToken({ userId: new ObjectId(user._id), token: refreshToken })
      )
      return {
        accessToken,
        refreshToken,
        newUser: 0,
        verify: user.verify
      }
    } else {
      const password = generateRandomPassword(20)
      const newUser = await this.Register({
        email: userInfo.email,
        name: userInfo.name,
        dateOfBirth: new Date().toISOString(),
        password,
        passwordConfirm: password
      })
      return {
        ...newUser,
        newUser: 1,
        verify: UserVerifyStatus.Unverified
      }
    }
  }
  async Logout(refresh_token: string) {
    await databaseService.RefeshTokens.deleteOne({ token: refresh_token })
    return {
      message: USER_MESSAGES.LOGOUT_SUCCESSFULLY
    }
  }
  async verifyEmail(userId: string) {
    const [token] = await Promise.all([
      this.signAccessTokenAndRefreshToken({
        userId,
        verify: UserVerifyStatus.Verified
      }),
      databaseService.users.updateOne(
        {
          _id: new ObjectId(userId)
        },

        {
          $set: {
            email_verify_token: '',
            verify: UserVerifyStatus.Verified
          },
          $currentDate: {
            updated_at: true
          }
        }
      )
    ])
    const [accessToken, refreshToken] = token
    await databaseService.RefeshTokens.insertOne(
      new RefreshToken({
        userId: new ObjectId(userId),
        token: refreshToken
      })
    )
    return {
      accessToken,
      refreshToken
    }
  }
  async resendVerifyEmail(userId: string) {
    console.log('Resend verify email')
    const email_verify_token = await this.signEmailVerifyToken({
      userId,
      verify: UserVerifyStatus.Unverified
    })
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(userId)
      },
      {
        $set: {
          email_verify_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USER_MESSAGES.RESEND_VERIFY_EMAIL_SUCCESSFULLY
    }
  }

  async forgotPassword({ userId, verify }: { userId: string; verify: UserVerifyStatus }) {
    const forgot_password_token = await this.signForgotPasswordToken({
      userId,
      verify
    })
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(userId)
      },
      {
        $set: {
          forgot_password_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USER_MESSAGES.CHECK_EMAIL_TO_RESET_PASSWORD
    }
  }

  async resetPassword(userId: string, password: string) {
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(userId)
      },
      {
        $set: {
          password: hashPassword(password),
          forgot_password_token: ''
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USER_MESSAGES.RESET_PASSWORD_SUCCESSFULLY
    }
  }

  async getProfile(userId: string) {
    const user = await databaseService.users.findOne(
      { _id: new ObjectId(userId) },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )
    return user
  }
  async updateProfile(userId: string, payload: UpdateProfileRequestBody) {
    const _payload = payload.dateOfBirth ? { ...payload, dateOfBirth: new Date(payload.dateOfBirth) } : payload
    const user = await databaseService.users.findOneAndUpdate(
      {
        _id: new ObjectId(userId)
      },
      {
        $set: _payload as UpdateProfileRequestBody & { dateOfBirth: Date },
        $currentDate: {
          updated_at: true
        }
      },
      {
        returnDocument: 'after',
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )
    return user.value
  }

  async getProfileByUsername(username: string) {
    const user = await databaseService.users.findOne(
      { username },
      {
        projection: {
          password: 0,
          created_at: 0,
          updated_at: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0
        }
      }
    )
    if (user === null) {
      throw new ErrorWithStatus({
        message: USER_MESSAGES.USER_NOT_FOUND,
        status: HttpStatusCode.NotFound
      })
    }
    return user
  }
  async follow(userId: string, followed_user_id: string) {
    const follower = await databaseService.Followers.findOne({
      userId: new ObjectId(userId),
      followed_user_id: new ObjectId(followed_user_id)
    })
    if (follower === null) {
      await databaseService.Followers.insertOne(
        new Follower({
          userId: new ObjectId(userId),
          followed_user_id: new ObjectId(followed_user_id)
        })
      )
      return {
        message: USER_MESSAGES.FOLLOW_USER_SUCCESSFULLY
      }
    }
    return {
      message: USER_MESSAGES.FOLLOWED
    }
  }
  async unfollow(userId: string, user_id_u_followed: string) {
    await databaseService.Followers.deleteOne({
      userId: new ObjectId(userId),
      followed_user_id: new ObjectId(user_id_u_followed)
    })
    return {
      message: USER_MESSAGES.UNFOLLOWED
    }
  }
  async changePassword(userId: string, passwordNew: string) {
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(userId)
      },
      {
        $set: {
          password: hashPassword(passwordNew)
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USER_MESSAGES.CHANGE_PASSWORD_SUCCESSFULLY
    }
  }
}

const usersServices = new UsersServices()
export default usersServices
