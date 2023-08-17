import { Request, Response } from 'express'
import User from '~/models/schemas/User.schema'
import databaseService from '~/services/database.services'
import usersServices from '~/services/users.services'

export const registerController = async (req: Request, res: Response) => {
  const { email, password } = req.body
  console.log(req.body)
  try {
    const result = await usersServices.Register({ email, password })
    return res.status(200).json({
      message: 'User registered successfully!',
      result: {
        email: email,
        accessToken: new Date().getTime()
      }
    })
  } catch (err) {
    return res.status(400).json({
      error: err
    })
  }
}
