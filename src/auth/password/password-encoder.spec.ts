import { BcryptPasswordEncoder } from './bcrypt-password-encoder';
import { Argon2PasswordEncoder } from './argon2-password-encoder';

describe('PasswordEncoder', () => {
  describe('BcryptPasswordEncoder', () => {
    it('should hash and verify password', async () => {
      const encoder = new BcryptPasswordEncoder(4);
      const hash = await encoder.hash('plain-password');

      expect(hash).toContain('$2b$');
      await expect(encoder.verify('plain-password', hash)).resolves.toBe(true);
      await expect(encoder.verify('wrong-password', hash)).resolves.toBe(false);
    });

    it('should use configurable rounds', async () => {
      const encoder = new BcryptPasswordEncoder(5);
      const hash = await encoder.hash('password');
      expect(hash.startsWith('$2b$05$')).toBe(true);
    });
  });

  describe('Argon2PasswordEncoder', () => {
    it('should hash and verify password', async () => {
      const encoder = new Argon2PasswordEncoder({
        type: 2, // argon2id
        timeCost: 2,
        memoryCost: 4096,
        parallelism: 1,
      });
      const hash = await encoder.hash('plain-password');

      expect(hash).toContain('$argon2id$');
      await expect(encoder.verify('plain-password', hash)).resolves.toBe(true);
      await expect(encoder.verify('wrong-password', hash)).resolves.toBe(false);
    });
  });
});
