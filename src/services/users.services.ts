import User from '~/models/schemas/User.schema'
import databaseService from './database.services'

class UsersServices {
  async Register(payload: { email: string; password: string }) {
    const { email, password } = payload
    const result = await databaseService.users.insertOne(new User({ email, password }))
    return result
  }
}
const usersServices = new UsersServices()
export default usersServices
