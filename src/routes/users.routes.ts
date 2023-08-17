import express from 'express'
import { registerController } from '~/controllers/users.controllers'
import { loginValidator } from '~/middlewares/users.middlewares'
const usersRouter = express.Router()

usersRouter.get('/users', (req: any, res: any) => {
  res.send(`<h1>Hello user</h1>`)
})
usersRouter.post('/register', loginValidator, registerController)
usersRouter.post('/login', loginValidator, (req: any, res: any) => {
  res.json({
    message: 'login thanh cong'
  })
  console.log('login run')
})

export default usersRouter
