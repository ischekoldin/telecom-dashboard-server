const cookieExpiresIn = (days) => {
    let date = new Date();
    date.setTime(date.setTime(date.getTime()+(days*24*60*60*1000)));
    return date;
};

module.exports = {cookieExpiresIn};
