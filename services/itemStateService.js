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
    DELETED: 'deleted',
    RETURNED: 'returned'
};

const transitions = {
    unassigned: ['assigned', 'deleted'],
    assigned: ['pending', 'unassigned', 'rejected', 'deleted'],
    rejected: ['assigned', 'deleted'],
    pending: ['approved', 'rejected'],
    approved: ['allocated', 'assigned', 'deleted'],
    allocated: ['received', 'deleted'],
    received: ['sent', 'returned'],
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

function transitionItem(currentStatus, nextStatus) {

    const allowed = transitions[currentStatus] || [];

    if (!allowed.includes(nextStatus)) {
        throw new Error(`Invalid transition: ${currentStatus} → ${nextStatus}`);
    }

    return nextStatus;
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

function donorCanDelete(status) {

    return [
        ITEM_STATUS.UNASSIGNED,
        ITEM_STATUS.ASSIGNED,
        ITEM_STATUS.REJECTED,
        ITEM_STATUS.APPROVED,
        ITEM_STATUS.ALLOCATED
    ].includes(status);

}

function charityAdminCanEdit(status) {
    return status === ITEM_STATUS.RECEIVED;
}

function charityAdminCanDelete(status) {
    return status === ITEM_STATUS.RECEIVED;
}

function charityAdminCanMarkReceived(status) {
    return status === ITEM_STATUS.ALLOCATED;
}

function charityAdminCanSend(status) {
    return status === ITEM_STATUS.RECEIVED;
}

function charityAdminCanReturn(status) {
    return status === ITEM_STATUS.RECEIVED;
}

function recipientCanConfirm(status) {
    return status === ITEM_STATUS.SENT;
}

function deleteItem(currentStatus, role) {

    if (role !== 'donor') return false;

    return [
        ITEM_STATUS.UNASSIGNED,
        ITEM_STATUS.ASSIGNED,
        ITEM_STATUS.REJECTED,
        ITEM_STATUS.APPROVED,
        ITEM_STATUS.ALLOCATED
    ].includes(currentStatus);

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
    transitionItem,
    canChangeStatus,
    deleteItem,
    donorCanDelete,
    donorCanFullyEdit,
    donorCanChangeCharity,
    charityAdminCanEdit,
    charityAdminCanDelete,
    charityAdminCanMarkReceived,
    charityAdminCanReturn,
    charityAdminCanSend,
    recipientCanConfirm,
    determineInitialStatus,
    determineStatusAfterEdit,
};