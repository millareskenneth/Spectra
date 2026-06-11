import { RES_005 } from '../rules/RES-005';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-005: Database Internals Leaked', () => {
  const mockReq = createMockRequest();

  it('should flag a PostgreSQL error', () => {
    const res = createMockResponse({
      body: 'PostgreSQL ERROR: relation "users" does not exist'
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('PostgreSQL Error');
  });

  it('should flag a MySQL syntax error', () => {
    const res = createMockResponse({
      body: 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('MySQL Error');
  });

  it('should flag an Oracle error code', () => {
    const res = createMockResponse({
      body: 'ORA-00942: table or view does not exist'
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Oracle Error');
  });

  it('should flag a MongoDB connection string', () => {
    const res = createMockResponse({
      body: JSON.stringify({
        db_url: 'mongodb+srv://admin:p@ssw0rd123@cluster0.abcde.mongodb.net/mydb'
      })
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Database Connection String');
  });

  it('should flag an ODBC connection string', () => {
    const res = createMockResponse({
      body: 'Server=myServerAddress;Database=myDataBase;User ID=myUsername;Password=myPassword;'
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('ODBC/JDBC Connection String');
  });

  it('should flag SQLite no such table error', () => {
    const res = createMockResponse({
      body: 'sqlite3.Error: no such table: secrets'
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('SQLite Error');
  });

  it('should not flag safe response bodies', () => {
    const res = createMockResponse({
      body: JSON.stringify({
        id: 123,
        status: 'active',
        message: 'Query successful'
      })
    });

    const finding = RES_005.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
