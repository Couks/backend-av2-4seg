import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';

// Pipe personalizado para validação de dados de entrada
@Injectable()
export class CustomValidationPipe implements PipeTransform<any> {
  // Transforma e valida os dados de entrada
  async transform(value: any, { metatype }: ArgumentMetadata) {
    // Se não houver metatype ou não precisar validar, retorna o valor original
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    // Converte o valor plano para uma instância da classe
    const object = plainToClass(metatype, value);
    // Executa a validação usando class-validator
    const errors = await validate(object);

    // Se houver erros de validação, formata e lança uma exceção
    if (errors.length > 0) {
      const messages = errors.map((err) => {
        return {
          property: err.property,
          constraints: err.constraints,
        };
      });

      throw new BadRequestException({
        message: 'Validation failed',
        errors: messages,
      });
    }

    return value;
  }

  // Verifica se o tipo precisa ser validado
  // Retorna falso para tipos primitivos e true para classes/DTOs
  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
