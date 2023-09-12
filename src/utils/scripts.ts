export function generateRandomPassword(length: number) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let password = ''

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length)
    password += charset.charAt(randomIndex)
  }

  return password
}

const randomPassword = generateRandomPassword(10)
console.log(randomPassword)
