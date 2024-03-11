const { DataTypes } = require('sequelize');
const sequelize = require('../utils/connection');

const EmailCode = sequelize.define('emailcode', {
    code: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    //userId
});

module.exports = EmailCode;