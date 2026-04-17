function redirectByRole(user, res) {
    const routes = {
        sys_admin: '/admin/dashboard',
        charity_admin: '/admin/charitydashboard',
        donor: '/items/my',
        recipient: '/homepage'
    };

    res.redirect(routes[user.role] || '/homepage');
}

module.exports = redirectByRole;