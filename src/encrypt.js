/**
 * Encrypt library for encrypt files using AES-256-GCM
 */

import crypto from 'crypto'

class Encrypt {
  constructor() {
    this.crypto = crypto
    
    // Bind all methods to maintain 'this' context
    this.encrypt = this.encrypt.bind(this)
    this.decrypt = this.decrypt.bind(this)
    this.generateKey = this.generateKey.bind(this)
    this.generateIV = this.generateIV.bind(this)
    this.getFileHash = this.getFileHash.bind(this)
  }

  encrypt(data, key) {
    return new Promise((resolve, reject) => {
      try {
        const iv = this.generateIV()
        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data)
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'))
  
        let encrypted = cipher.update(dataBuffer)
        encrypted = Buffer.concat([encrypted, cipher.final()])
  
        // Get the auth tag for GCM
        const authTag = cipher.getAuthTag()
        
        // Concatenate IV + encrypted data + auth tag
        const encryptedWithIvAndTag = Buffer.concat([
          Buffer.from(iv, 'hex'), 
          encrypted, 
          authTag
        ])
        resolve(encryptedWithIvAndTag)
      } catch (error) {
        reject(error)
      }
    })
  }

  decrypt(data, key) {
    return new Promise((resolve, reject) => {
      try {
        // Convert hex string to Buffer if needed
        const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'hex') : Buffer.isBuffer(data) ? data : Buffer.from(data)
        
        // Extract IV (12 bytes), auth tag (16 bytes), and encrypted data
        const iv = Buffer.from(dataBuffer.subarray(0, 12))
        const authTag = Buffer.from(dataBuffer.subarray(dataBuffer.length - 16))
        const encrypted = Buffer.from(dataBuffer.subarray(12, dataBuffer.length - 16))

        console.log('dataBuffer length:', dataBuffer.length)
        console.log('encrypted length:', encrypted.length)
        console.log('iv length:', iv.length)
        console.log('authTag length:', authTag.length)

        const decipher = this.crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv)
        decipher.setAuthTag(authTag)
        
        let decrypted = decipher.update(encrypted)
        decrypted = Buffer.concat([decrypted, decipher.final()])
        resolve(decrypted)
      } catch (error) {
        reject(error)
      }
    })
  }

  generateKey() {
    return this.crypto.randomBytes(32).toString('hex')
  }

  generateIV() {
    // GCM requires 12 bytes (96 bits) for the IV
    return this.crypto.randomBytes(12).toString('hex')
  }




  async getFileHash(data) {
    return new Promise((resolve , reject)=>{
      try {
        // Ensure data is a Buffer
        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data)
        
        // Generate SHA-256 hash
        const hash = this.crypto.createHash('sha256')
        hash.update(dataBuffer)
        resolve(hash.digest('hex'))
      } catch (error) {
        reject(error)
      }
    })

  }



}

export default Encrypt