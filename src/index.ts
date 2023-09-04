import express from 'express'
import usersRouter from '~/routes/users.routes'
import databaseService from '~/services/database.services'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import { config } from 'dotenv'
config()
const port = process.env.PORT || 4000
const app = express()

app.use(express.json())
app.use('/users', usersRouter)
app.use(defaultErrorHandler)

databaseService.connect()
app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})
