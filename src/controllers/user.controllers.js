const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');


const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const result = await User.create({ ...req.body, password: hashedPassword })

  const code = require('crypto').randomBytes(32).toString('hex')
  const link = `${req.body.frontBaseUrl}/${code}`

  await EmailCode.create({ code, userId: result.id })

  await sendEmail({
    to: req.body.email,
    subject: "Welcome to Verification APP!",
    html: `
     <h1>Hello ${req.body.firstName} ${req.body.lastName}</h1>
     <p><a href="${link}">${link}</a></p>
     <p><b>Code: </b> ${code}</p>
     <p><b>Thanks for sign up in Verification App</b></p>
    `
  })
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { email, firstName, lastName, country, image } = req.body
  const result = await User.update(
    { email, firstName, lastName, country, image },
    { where: { id }, returning: true }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyEmail = catchError(async (req, res) => {
  const { code } = req.params
  const emailcode = await EmailCode.findOne({
    where: { code: code }
  })
  if (!emailcode) return res.status(401).json({ message: 'Código inválido' })

  const userUpdate = await User.update(
    { isVerified: true },
    { where: { id: emailcode.userId }, returning: true }
  )

  await emailcode.destroy()

  return res.json(userUpdate[1][0])
})

const login = catchError(async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ where: { email: email } })
  if (!user) return res.status(401).json({ message: "invalid credentials" })
  const isValid = await bcrypt.compare(password, user.password)
  if (!isValid) return res.status(401).json({ message: "Invalid credentials" })
  if (!user.isVerified) return res.status(401).json({ message: "Unverified user" })

  const token = jwt.sign(
    { user },
    process.env.TOKEN_SECRET,
    { expiresIn: "1d" }
  )

  return res.json({ user: user, token: token })
})

const loggedUser = catchError(async (req, res) => {
  return res.json(req.user)
})

const resetPass = catchError(async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } })
  if (!user) return res.status(401).json({ message: "invalid credentials" })

  const code = require('crypto').randomBytes(32).toString('hex')
  const link = `${req.body.frontBaseUrl}/${code}`

  await EmailCode.create({ code, userId: user.id })

  await sendEmail({
    to: req.body.email,
    subject: "Password recovery!",
    html: `
     <h1>Hello ${req.body.firstName} ${req.body.lastName}</h1>
     <p><b>Click the following link to recover your password</b></p>
     <p><a href="${link}">${link}</a></p>
     <p><b>Code: </b> ${code}</p>
    `
  })

  return res.status(200).json({ message: `Recovery link sent to ${req.body.email}` })

})

const newPass = catchError(async (req, res) => {
  const emailcode = await EmailCode.findOne({
    where: { code: req.params.code }
  })
  if (!emailcode) return res.status(401).json({ message: 'Código inválido' })
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const userUpdate = await User.update(
    { password: hashedPassword },
    { where: { id: emailcode.userId }, returning: true }
  );
  await emailcode.destroy()
  return res.json(userUpdate[1][0])
})

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyEmail,
  login,
  loggedUser,
  resetPass,
  newPass
}