// services/itemStateService.js

const ITEM_STATUS = {
    UNASSIGNED: 'unassigned',
    ASSIGNED: 'assigned',
    PENDING: 'pending',
    APPROVED: 'approved',
    ALLOCATED: 'allocated',
    RECEIVED: 'received',
    SENT: 'sent',
    DELIVERED: 'delivered',
    NEVER_ARRIVED: 'never_arrived',
    REJECTED: 'rejected',
    DELETED: 'deleted'
};

const transitions = {
    unassigned: ['assigned', 'deleted'],
    assigned: ['pending', 'unassigned', 'rejected', 'deleted'],
    rejected: ['assigned', 'deleted'],
    pending: ['approved', 'rejected'],
    approved: ['allocated', 'assigned', 'deleted'],
    allocated: ['received', 'deleted'],
    received: ['sent'],
    sent: ['delivered', 'never_arrived'],
    delivered: [],
    never_arrived: [],
    deleted: []
};

function determineInitialStatus(charityId) {

    if (!charityId || charityId === '') {
        return {
            status: ITEM_STATUS.UNASSIGNED,
            charity_id: null
        };
    }

    return {
        status: ITEM_STATUS.ASSIGNED,
        charity_id: charityId
    };
}

function determineStatusAfterEdit(currentStatus, role, oldCharityId, newCharityId) {

    // Normalise empty values
    const newId = newCharityId || null;
    const oldId = oldCharityId || null;

    // CASE 1:
    // Unassigned → charity added
    if (
        currentStatus === ITEM_STATUS.UNASSIGNED &&
        newId !== null
    ) {
        return ITEM_STATUS.ASSIGNED;
    }

    // CASE 2:
    // Assigned → charity removed
    if (
        currentStatus === ITEM_STATUS.ASSIGNED &&
        newId === null
    ) {
        return ITEM_STATUS.UNASSIGNED;
    }

    // CASE 3:
    // Approved → charity changed
    if (
        role === 'donor' &&
        currentStatus === ITEM_STATUS.APPROVED &&
        oldId !== newId
    ) {
        return ITEM_STATUS.ASSIGNED;
    }

    return currentStatus;
}

function canTransition(currentStatus, newStatus) {
    return transitions[currentStatus]?.includes(newStatus);
}

function canEditItem(role, status, action = 'edit') {

    // Donor full edit
    if (role === 'donor' &&
        ['unassigned', 'assigned', 'rejected'].includes(status)) {
        return true;
    }

    // Donor special case: approved → only charity change
    if (role === 'donor' &&
        status === 'approved' &&
        action === 'change_charity') {
        return true;
    }

    // Charity admin after item received
    if (role === 'charity_admin' && status === 'received') {
        return true;
    }

    return false;
}

function canTransition(currentStatus, newStatus) {
    return transitions[currentStatus]?.includes(newStatus);
}

function canEditItem(role, status, action = 'edit') {

    // Donor full edit
    if (role === 'donor' &&
        ['unassigned', 'assigned', 'rejected'].includes(status)) {
        return true;
    }

    // Donor special case: approved → only charity change
    if (role === 'donor' &&
        status === 'approved' &&
        action === 'change_charity') {
        return true;
    }

    // Charity admin after item received
    if (role === 'charity_admin' && status === 'received') {
        return true;
    }

    return false;
}

module.exports = {
    ITEM_STATUS,
    canTransition,
    canEditItem,
    canChangeStatus,
    determineInitialStatus,
    determineStatusAfterEdit,
};