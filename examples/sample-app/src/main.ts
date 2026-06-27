import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  await app.listen(3100);
  console.log('Sample auth app is running on http://localhost:3100');
}

void bootstrap();
