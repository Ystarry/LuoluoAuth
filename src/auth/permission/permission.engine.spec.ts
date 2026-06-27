import { PermissionEngine } from './permission.engine';

describe('PermissionEngine', () => {
  let engine: PermissionEngine;

  beforeEach(() => {
    engine = new PermissionEngine();
  });

  describe('hasRole', () => {
    it('should return true when no roles required', () => {
      const session = { userId: '1', createTime: Date.now() };
      expect(engine.hasRole(session, [])).toBe(true);
      expect(engine.hasRole(session, undefined as unknown as string[])).toBe(
        true,
      );
    });

    it('should return true when user has one of required roles', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        roles: ['user', 'editor'],
      };
      expect(engine.hasRole(session, ['admin', 'user'])).toBe(true);
    });

    it('should return false when user has none of required roles', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        roles: ['user'],
      };
      expect(engine.hasRole(session, ['admin'])).toBe(false);
    });
  });

  describe('hasPermission', () => {
    it('should return true when no permissions required', () => {
      const session = { userId: '1', createTime: Date.now() };
      expect(engine.hasPermission(session, [])).toBe(true);
    });

    it('should return true when user has exact permissions', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        permissions: ['user:add', 'user:delete'],
      };
      expect(engine.hasPermission(session, ['user:add'])).toBe(true);
    });

    it('should return false when user lacks required permissions', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        permissions: ['user:add'],
      };
      expect(engine.hasPermission(session, ['user:delete'])).toBe(false);
    });

    it('should support wildcard matching with user:*', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        permissions: ['user:*'],
      };
      expect(engine.hasPermission(session, ['user:add'])).toBe(true);
      expect(engine.hasPermission(session, ['user:delete'])).toBe(true);
      expect(engine.hasPermission(session, ['user:admin:delete'])).toBe(false);
    });

    it('should support global wildcard *', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        permissions: ['*'],
      };
      expect(engine.hasPermission(session, ['anything'])).toBe(true);
      expect(engine.hasPermission(session, ['user:add', 'order:pay'])).toBe(
        true,
      );
    });

    it('should match all required permissions', () => {
      const session = {
        userId: '1',
        createTime: Date.now(),
        permissions: ['user:add', 'user:delete'],
      };
      expect(engine.hasPermission(session, ['user:add', 'user:delete'])).toBe(
        true,
      );
      expect(engine.hasPermission(session, ['user:add', 'user:update'])).toBe(
        false,
      );
    });
  });
});
