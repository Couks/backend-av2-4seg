import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';

/**
 * Pipe de validação customizado para validar dados de entrada
 *
 * Este pipe é responsável por:
 * - Transformar dados de entrada em instâncias de classes DTO
 * - Validar os dados usando class-validator
 * - Formatar e retornar erros de validação
 */
@Injectable()
export class CustomValidationPipe implements PipeTransform<any> {
  /**
   * Transforma e valida os dados de entrada
   * @param value - Valor a ser transformado/validado
   * @param metatype - Tipo de metadados do parâmetro
   * @returns Valor validado ou lança exceção se inválido
   */
  async transform(value: any, { metatype }: ArgumentMetadata) {
    // Pula validação se não houver metatype ou for tipo primitivo
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    // Transforma o valor plano em instância da classe
    const object = plainToClass(metatype, value);
    // Executa a validação usando class-validator
    const errors = await validate(object);

    // Se houver erros, formata e lança exceção
    if (errors.length > 0) {
      const messages = errors.map((err) => {
        return {
          property: err.property, // Nome do campo com erro
          constraints: err.constraints, // Restrições violadas
        };
      });

      throw new BadRequestException({
        message: 'Validation failed',
        errors: messages,
      });
    }

    return value;
  }

  /**
   * Verifica se o tipo deve ser validado
   * @param metatype - Tipo a ser verificado
   * @returns true se o tipo deve ser validado, false caso contrário
   */
  private toValidate(metatype: Function): boolean {
    // Lista de tipos primitivos que não precisam validação
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
