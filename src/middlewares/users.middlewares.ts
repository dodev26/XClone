import { config } from 'dotenv'
import { Request } from 'express'
import { ParamSchema, checkSchema } from 'express-validator'
import { JsonWebTokenError } from 'jsonwebtoken'
import { capitalize } from 'lodash'
import { ObjectId } from 'mongodb'
import { HttpStatusCode, UserVerifyStatus } from '~/constants/enum'
import { USER_MESSAGES } from '~/constants/messages'
import { REGEX_USERNAME } from '~/constants/regexs'
import { ErrorWithStatus } from '~/models/Errors'
import { TokenPayload } from '~/models/requests/User.requests'
import User from '~/models/schemas/User.schema'
import databaseService from '~/services/database.services'
import { hashPassword } from '~/utils/crypto'
import { verifyToken } from '~/utils/jwt'
import { validate } from '~/utils/validation'
config()

const passwordSchema: ParamSchema = {
  notEmpty: {
    errorMessage: USER_MESSAGES.PASSWORD_IS_REQUIRED
  },
  isString: {
    errorMessage: USER_MESSAGES.PASSWORD_MUST_BE_A_STRING
  },
  isLength: {
    options: {
      min: 6,
      max: 50
    },
    errorMessage: USER_MESSAGES.PASSWORD_LENGTH
  },
  isStrongPassword: {
    options: {
      minLength: 6,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1
    },
    errorMessage: USER_MESSAGES.PASSWORD_MUST_BE_STRONG
  }
}

const passwordConfirmSchema = (key: string): ParamSchema => ({
  notEmpty: {
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_IS_REQUIRED
  },
  isString: {
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_MUST_BE_STRING
  },
  isLength: {
    options: {
      min: 6,
      max: 50
    },
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_LENGTH
  },
  isStrongPassword: {
    options: {
      minLength: 6,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1
    },
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_MUST_BE_STRONG
  },
  custom: {
    options: (value, { req }) => {
      if (value !== req.body[key]) {
        throw new Error(USER_MESSAGES.CONFIRM_PASSWORD_MUST_BE_EQUAL_PASSWORD)
      }
      return true
    }
  }
})

const nameSchema: ParamSchema = {
  notEmpty: {
    errorMessage: USER_MESSAGES.NAME_IS_REQUIRED
  },
  isString: {
    errorMessage: USER_MESSAGES.NAME_MUST_BE_A_STRING
  },
  isLength: {
    options: {
      min: 1,
      max: 100
    },
    errorMessage: USER_MESSAGES.NAME_LENGTH
  },
  trim: true
}

const dateOfBirthSchema: ParamSchema = {
  notEmpty: {
    errorMessage: USER_MESSAGES.DATE_OF_BIRTH_IS_REQUIRED
  },
  isISO8601: {
    options: {
      strict: true,
      strictSeparator: true
    },
    errorMessage: USER_MESSAGES.DATE_OF_BIRTH_MUST_BE_ISO8601_DATE
  }
}

const forgotPasswordTokenSchema: ParamSchema = {
  trim: true,
  custom: {
    options: async (value: string, { req }) => {
      try {
        const forgot_password_token = value
        if (!forgot_password_token) {
          throw new ErrorWithStatus({
            message: USER_MESSAGES.FORGOT_PASSWORD_TOKEN_IS_REQUIRED,
            status: HttpStatusCode.Unauthorized
          })
        }
        const decoded_forgot_password_verify_token = await verifyToken({
          token: forgot_password_token,
          secretOrPublickey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN as string
        })
        const { userId } = decoded_forgot_password_verify_token
        const user = await databaseService.users.findOne({ _id: new ObjectId(userId) })
        if (user === null) {
          throw new ErrorWithStatus({
            message: USER_MESSAGES.USER_NOT_FOUND,
            status: HttpStatusCode.Unauthorized
          })
        }
        if (user.forgot_password_token !== forgot_password_token) {
          throw new ErrorWithStatus({
            message: USER_MESSAGES.FORGOT_PASSWORD_TOKEN_IS_INVALID,
            status: HttpStatusCode.Unauthorized
          })
        }
        ;(req as Request).decoded_forgot_password_verify_token = decoded_forgot_password_verify_token
        return true
      } catch (error) {
        if (error instanceof JsonWebTokenError) {
          throw new ErrorWithStatus({
            message: capitalize(error.message),
            status: HttpStatusCode.Unauthorized
          })
        }
        throw error
      }
    }
  }
}

const imageUrlSchema: ParamSchema = {
  optional: true,
  isString: {
    errorMessage: 'Image url must be a string'
  },
  // trim: true,
  isLength: {
    options: {
      min: 1,
      max: 400
    },
    errorMessage: USER_MESSAGES.IMAGE_URL_LENGTH
  }
}

export const registerValidator = validate(
  checkSchema(
    {
      name: nameSchema,
      email: {
        notEmpty: {
          errorMessage: USER_MESSAGES.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USER_MESSAGES.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const email = value
            const user = await databaseService.users.findOne({ email })

            if (user) {
              throw new Error(USER_MESSAGES.EMAIL_ALREADY_EXISTS)
            }
            req.user = user
            return true
          }
        }
      },
      password: passwordSchema,
      passwordConfirm: passwordConfirmSchema('passwordConfirm'),
      dateOfBirth: dateOfBirthSchema
    },
    ['body']
  )
)

export const loginValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: {
          errorMessage: USER_MESSAGES.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USER_MESSAGES.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const email = value
            const password = req.body.password
            const user = await databaseService.users.findOne({ email, password: hashPassword(password) })
            if (user === null) {
              throw new Error(USER_MESSAGES.EMAIL_OR_PASSWORD_IS_INVALID)
            }
            req.user = user
            return true
          }
        }
      },
      password: passwordSchema
    },
    ['body']
  )
)

export const accessTokenValidator = validate(
  checkSchema(
    {
      Authorization: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            try {
              const access_token = value
              if (!access_token) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGES.ACCESS_TOKEN_IS_REQUIRED,
                  status: HttpStatusCode.Unauthorized
                })
              }
              const access_token_splited = access_token.split(' ')[1]
              const decoded_authorization = await verifyToken({
                token: access_token_splited,
                secretOrPublickey: process.env.JWT_SECRET_ACCESS_TOKEN as string
              })
              ;(req as Request).decoded_authorization = decoded_authorization
              return true
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: capitalize(error.message),
                  status: HttpStatusCode.Unauthorized
                })
              }
              throw error
            }
            return true
          }
        }
      }
    },
    ['headers']
  )
)

export const refreshTokenValidator = validate(
  checkSchema(
    {
      refresh_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            try {
              const refresh_token_body = value
              if (!refresh_token_body) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGES.REFRESH_TOKEN_IS_REQUIRED,
                  status: HttpStatusCode.Unauthorized
                })
              }
              const reqList = [
                verifyToken({
                  token: refresh_token_body,
                  secretOrPublickey: process.env.JWT_SECRET_REFRESH_TOKEN as string
                }),
                databaseService.RefeshTokens.findOne({ token: refresh_token_body })
              ]
              const [decoded_refresh_token, refresh_token] = await Promise.all(reqList)
              if (refresh_token === null) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGES.REFRESH_TOKEN_WAS_USED_OR_NOT_EXIST,
                  status: HttpStatusCode.Unauthorized
                })
              }
              ;(req as Request).decoded_refresh_token = decoded_refresh_token as TokenPayload
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGES.REFRESH_TOKEN_IS_INVALID,
                  status: HttpStatusCode.Unauthorized
                })
              }
              throw error
            }
          }
        }
      }
    },
    ['body']
  )
)

export const emailVerifyValidator = validate(
  checkSchema(
    {
      email_verify_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            try {
              const email_verify_token = value
              if (!email_verify_token) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGES.EMAIL_VERIFY_TOKEN_IS_REQUIRED,
                  status: HttpStatusCode.Unauthorized
                })
              }
              const decoded_email_verify_token = await verifyToken({
                token: email_verify_token,
                secretOrPublickey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN as string
              })
              console.log('decoded_email_verify_token', decoded_email_verify_token)
              ;(req as Request).decoded_email_verify_token = decoded_email_verify_token
              return true
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: USER_MESSAGES.EMAIL_VERIFY_TOKEN_IS_INVALID,
                  status: HttpStatusCode.Unauthorized
                })
              }
              throw error
            }
          }
        }
      }
    },
    ['body']
  )
)

export const forgotPasswordValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: {
          errorMessage: USER_MESSAGES.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USER_MESSAGES.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const email = value
            const user = await databaseService.users.findOne({ email })
            if (user === null) {
              throw new Error(USER_MESSAGES.USER_NOT_FOUND)
            }
            req.user = user
            return true
          }
        }
      }
    },
    ['body']
  )
)

export const verifyForgotPasswordTokenValidator = validate(
  checkSchema(
    {
      forgot_password_token: forgotPasswordTokenSchema
    },
    ['body']
  )
)

export const resetPasswordValidator = validate(
  checkSchema(
    {
      password: passwordSchema,
      passwordConfirm: passwordConfirmSchema('passwordConfirm'),
      forgot_password_token: forgotPasswordTokenSchema
    },
    ['body']
  )
)

export const verifiedUserValidator = async (req: Request, res: any, next: any) => {
  const { verify } = req.decoded_authorization as TokenPayload
  if (verify !== UserVerifyStatus.Verified) {
    next(new ErrorWithStatus({ message: USER_MESSAGES.USER_NOT_VERIFIED, status: HttpStatusCode.Forbidden }))
  }
  next()
}

export const updateProfileValidator = validate(
  checkSchema(
    {
      name: {
        ...nameSchema,
        optional: true,
        notEmpty: undefined
      },
      dateOfBirth: {
        ...dateOfBirthSchema,
        optional: true,
        notEmpty: undefined
      },
      bio: {
        optional: true,
        isString: {
          errorMessage: USER_MESSAGES.BIO_MUST_BE_A_STRING
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: USER_MESSAGES.BIO_LENGTH
        }
      },
      location: {
        optional: true,
        isString: {
          errorMessage: USER_MESSAGES.LOCATION_MUST_BE_A_STRING
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: USER_MESSAGES.LOCATION_LENGTH
        }
      },
      website: {
        optional: true,
        isString: {
          errorMessage: USER_MESSAGES.WEBSITE_MUST_BE_A_STRING
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: USER_MESSAGES.WEBSITE_LENGTH
        }
      },
      username: {
        optional: true,
        isString: {
          errorMessage: USER_MESSAGES.USER_NAME_MUST_BE_A_STRING
        },
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            const username = value
            if (!REGEX_USERNAME.test(username)) {
              throw Error(USER_MESSAGES.USERNAME_IS_INVALID)
            }
            const user = await databaseService.users.findOne({ username })
            if (user) {
              throw Error(USER_MESSAGES.USERNAME_IS_EXISTED)
            }
            return true
          }
        }
      },
      avatar: {
        ...imageUrlSchema,
        isString: {
          errorMessage: USER_MESSAGES.AVATAR_IMAGE_URL_MUST_BE_A_STRING
        }
      },
      cover_photo: {
        ...imageUrlSchema,
        isString: {
          errorMessage: USER_MESSAGES.COVER_PHOTO_IMAGE_URL_MUST_BE_A_STRING
        }
      }
    },
    ['body']
  )
)

export const followValidator = validate(
  checkSchema(
    {
      followed_user_id: {
        notEmpty: {
          errorMessage: USER_MESSAGES.USER_ID_IS_REQUIRED
        },
        custom: {
          options: async (value: string, { req }) => {
            const followed_user_id = value
            if (!ObjectId.isValid(followed_user_id)) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.USER_ID_IS_INVALID,
                status: HttpStatusCode.NotFound
              })
            }
            if (followed_user_id === (req.decoded_authorization as TokenPayload).userId) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.CAN_NOT_FOLLOW_YOURSELF,
                status: HttpStatusCode.Forbidden
              })
            }
            const followed_user = await databaseService.users.findOne({ _id: new ObjectId(followed_user_id) })
            if (followed_user === null) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.USER_NOT_FOUND,
                status: HttpStatusCode.NotFound
              })
            }
            if (followed_user && followed_user.verify === UserVerifyStatus.Unverified) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.CAN_NOT_FOLLOW_USER_NOT_VERIFIED,
                status: HttpStatusCode.Forbidden
              })
            }

            return true
          }
        }
      }
    },
    ['body']
  )
)

export const unfollowValidator = validate(
  checkSchema(
    {
      userId: {
        notEmpty: {
          errorMessage: USER_MESSAGES.USER_ID_IS_REQUIRED
        },
        custom: {
          options: async (value: string, { req }) => {
            const userId = value
            if (!ObjectId.isValid(userId)) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.USER_ID_IS_INVALID,
                status: HttpStatusCode.NotFound
              })
            }
            if (userId === (req.decoded_authorization as TokenPayload).userId) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.INVALID_OPERATION,
                status: HttpStatusCode.BadRequest
              })
            }
            const followed_user = await databaseService.users.findOne({ _id: new ObjectId(userId) })
            if (followed_user === null) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.USER_NOT_FOUND,
                status: HttpStatusCode.NotFound
              })
            }

            const not_followed_user = await databaseService.Followers.findOne({
              userId: new ObjectId((req.decoded_authorization as TokenPayload).userId),
              followed_user_id: new ObjectId(userId)
            })
            if (not_followed_user === null) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.YOU_NOT_FOLLOW_THIS_USER,
                status: HttpStatusCode.Conflict
              })
            }
            return true
          }
        }
      }
    },
    ['params']
  )
)

export const changePasswordValidator = validate(
  checkSchema(
    {
      passwordOld: {
        ...passwordSchema,
        custom: {
          options: async (value: string, { req }) => {
            const passwordOld = value
            const { userId } = req.decoded_authorization as TokenPayload
            const user = await databaseService.users.findOne({
              _id: new ObjectId(userId)
            })
            if (user === null) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.USER_NOT_FOUND,
                status: HttpStatusCode.NotFound
              })
            }
            const { password } = user
            const isMatch = password === hashPassword(passwordOld)
            if (!isMatch) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.PASSWORD_OLD_NOT_MATCH,
                status: HttpStatusCode.Unauthorized
              })
            }
            return true
          }
        }
      },
      passwordNew: passwordSchema,
      passswordConfirm: passwordConfirmSchema('passwordNew')
    },
    ['body']
  )
)
