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
    // Rejected → charity added again
    if (
        currentStatus === ITEM_STATUS.REJECTED &&
        newId !== null
    ) {
        return ITEM_STATUS.ASSIGNED;
    }

    // CASE 4:
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

function donorCanFullyEdit(status) {
    return [
        ITEM_STATUS.UNASSIGNED,
        ITEM_STATUS.ASSIGNED,
        ITEM_STATUS.REJECTED
    ].includes(status);
}

function donorCanChangeCharity(status) {
    return status === ITEM_STATUS.APPROVED;
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

function canChangeStatus(role, currentStatus, newStatus) {

    const roleTransitions = {
        donor: ['assigned', 'unassigned'],
        charity_admin: ['approved', 'rejected', 'allocated', 'received', 'sent'],
        recipient: ['delivered', 'never_arrived'],
        sys_admin: Object.values(ITEM_STATUS)
    };

    return roleTransitions[role]?.includes(newStatus);
}



module.exports = {
    ITEM_STATUS,
    canTransition,
    canChangeStatus,
    donorCanFullyEdit,
    donorCanChangeCharity,
    determineInitialStatus,
    determineStatusAfterEdit,
};