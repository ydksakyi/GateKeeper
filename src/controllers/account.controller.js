import { validationError, AppError } from '../utils/AppError.js';
import * as v from '../validators/index.js';
import * as users from '../db/users.js';

export async function updateProfile(req, res) {
  const { value, errors } = v.validateProfile(req.body);
  if (errors) throw validationError(errors);
  const user = await users.updateName(req.user.id, value.name);
  if (!user) throw new AppError(404, 'NOT_FOUND', 'User not found.');
  res.json({ user });
}
