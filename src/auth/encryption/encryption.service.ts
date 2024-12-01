import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

/**
 * Serviço responsável pela criptografia e hash de dados sensíveis
 *
 * Este serviço fornece métodos para:
 * - Hash e verificação de senhas usando bcrypt
 * - Criptografia e descriptografia de dados usando AES-256-GCM
 */
@Injectable()
export class EncryptionService {
  // Algoritmo AES-256-GCM para criptografia simétrica
  private readonly algorithm = 'aes-256-gcm';

  // Chave de criptografia derivada usando scrypt para maior segurança
  private readonly key = crypto.scryptSync(
    process.env.ENCRYPTION_KEY || 'your-secret-key',
    'salt',
    32, // Tamanho da chave em bytes
  );

  /**
   * Gera um hash seguro de senha usando bcrypt
   * @param password - Senha em texto plano
   * @returns Hash da senha
   */
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12); // 12 rounds de salt
  }

  /**
   * Compara uma senha em texto plano com um hash
   * @param plainText - Senha em texto plano
   * @param hashedPassword - Hash da senha armazenado
   * @returns true se as senhas correspondem, false caso contrário
   */
  async comparePasswords(
    plainText: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainText, hashedPassword);
  }

  /**
   * Criptografa um texto usando AES-256-GCM
   * @param text - Texto a ser criptografado
   * @returns Objeto contendo dados criptografados, vetor de inicialização e tag de autenticação
   */
  encrypt(text: string): {
    encryptedData: string;
    iv: string;
    authTag: string;
  } {
    // Gera um vetor de inicialização (IV) aleatório
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

    // Criptografa o texto
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'), // Tag para verificar integridade
    };
  }

  /**
   * Descriptografa dados criptografados com AES-256-GCM
   * @param encryptedData - Dados criptografados em formato hex
   * @param iv - Vetor de inicialização em formato hex
   * @param authTag - Tag de autenticação em formato hex
   * @returns Texto descriptografado
   */
  decrypt(encryptedData: string, iv: string, authTag: string): string {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      this.key,
      Buffer.from(iv, 'hex'),
    );

    // Define a tag de autenticação para verificar integridade
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    // Descriptografa os dados
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
