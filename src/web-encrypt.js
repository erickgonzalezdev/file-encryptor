class WebEncrypt {
  constructor() {
    this.encrypt = this.encrypt.bind(this)
    this.decrypt = this.decrypt.bind(this)
    this.generateKey = this.generateKey.bind(this)
    this.generateIV = this.generateIV.bind(this)
    this.getFileHash = this.getFileHash.bind(this)
  }

  async encrypt(data, keyHex) {
    const iv = this.generateIV()
    const key = await this.importKey(keyHex)

    const enc = new TextEncoder()
    const dataBuffer = typeof data === 'string' ? enc.encode(data) : data

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      dataBuffer
    )

    // Combine IV + encrypted data
    const result = new Uint8Array(iv.byteLength + encrypted.byteLength)
    result.set(iv, 0)
    result.set(new Uint8Array(encrypted), iv.byteLength)

    return result
  }

  async decrypt(encryptedData, keyHex) {
    const key = await this.importKey(keyHex)

    const iv = encryptedData.slice(0, 12)
    const data = encryptedData.slice(12)

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    )

    return new Uint8Array(decrypted)
  }

  generateKey() {
    const key = crypto.getRandomValues(new Uint8Array(32))
    return this.bufferToHex(key)
  }

  generateIV() {
    return crypto.getRandomValues(new Uint8Array(12))
  }

  async getFileHash(data) {
    const buffer = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data

    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
    return this.bufferToHex(new Uint8Array(hashBuffer))
  }

  // Helpers
  async importKey(keyHex) {
    const keyBuffer = this.hexToBuffer(keyHex)
    return crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    )
  }

  hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
    }
    return bytes
  }

  bufferToHex(buffer) {
    return [...buffer].map(b => b.toString(16).padStart(2, '0')).join('')
  }
}

export default WebEncrypt