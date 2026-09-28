import { AppError, validationError } from '../utils/AppError.js';
import * as v from '../validators/index.js';
import * as users from '../db/users.js';

export async function listUsers(req, res) {
  const { page, pageSize } = v.parsePagination(req.query);
  const [rows, total] = await Promise.all([users.list({ limit: pageSize, offset: (page - 1) * pageSize }), users.count()]);
  res.json({ users: rows, page, pageSize, total });
}

export async function updateRole(req, res) {
  const { id } = req.params;
  if (!v.isUuid(id)) throw validationError({ id: 'Invalid user id.' });
  const { value, errors } = v.validateRoleChange(req.body);
  if (errors) throw validationError(errors);
  // Prevents the last admin from demoting themselves and locking everyone out.
  if (id === req.user.id) throw new AppError(409, 'CANNOT_MODIFY_SELF', 'You cannot change your own role.');

  const user = await users.updateRole(id, value.role);
  if (!user) throw new AppError(404, 'NOT_FOUND', 'User not found.');
  res.json({ user });
}
