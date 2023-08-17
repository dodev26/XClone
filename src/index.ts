import express from 'express'
import usersRouter from '~/routes/users.routes'
import databaseService from '~/services/database.services'

const port = process.env.PORT || 4000
const app = express()

app.use(express.json())
app.use('/api/v1', usersRouter)
databaseService.connect()
app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})
