import { ObjectId } from 'mongodb'

interface FollowerType {
  _id?: ObjectId
  userId: ObjectId
  followed_user_id: ObjectId
  created_at?: Date
}

export default class Follower {
  _id?: ObjectId
  userId: ObjectId
  followed_user_id: ObjectId
  created_at: Date
  constructor({ followed_user_id, userId, _id, created_at }: FollowerType) {
    this._id = _id
    this.userId = userId
    this.followed_user_id = followed_user_id
    this.created_at = created_at || new Date()
  }
}
