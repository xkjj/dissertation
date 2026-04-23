// tests/itemStateService.test.js

const {
    donorCanFullyEdit,
    donorCanDelete,
    donorCanChangeCharity,
    determineInitialStatus,
    determineStatusAfterEdit,
    transitionItem,
    charityAdminCanMarkReceived,
    charityAdminCanSend,
    charityAdminCanReturn,
    recipientCanConfirm
} = require('../services/itemStateService');

// ─── donorCanFullyEdit ───────────────────────────────────────────────────────
describe('donorCanFullyEdit', () => {

    test('1 - returns true for unassigned status', () => {
        expect(donorCanFullyEdit('unassigned')).toBe(true);
    });

    test('2 - returns true for assigned status', () => {
        expect(donorCanFullyEdit('assigned')).toBe(true);
    });

    test('3 - returns true for rejected status', () => {
        expect(donorCanFullyEdit('rejected')).toBe(true);
    });

    test('4 - returns false for approved status', () => {
        expect(donorCanFullyEdit('approved')).toBe(false);
    });

    test('5 - returns false for delivered status', () => {
        expect(donorCanFullyEdit('delivered')).toBe(false);
    });

    test('6 - returns false for allocated status', () => {
        expect(donorCanFullyEdit('allocated')).toBe(false);
    });

    test('7 - returns false for received status', () => {
        expect(donorCanFullyEdit('received')).toBe(false);
    });

});

// ─── donorCanDelete ──────────────────────────────────────────────────────────
describe('donorCanDelete', () => {

    test('8 - returns true for unassigned status', () => {
        expect(donorCanDelete('unassigned')).toBe(true);
    });

    test('9 - returns true for assigned status', () => {
        expect(donorCanDelete('assigned')).toBe(true);
    });

    test('10 - returns true for rejected status', () => {
        expect(donorCanDelete('rejected')).toBe(true);
    });

    test('11 - returns true for approved status', () => {
        expect(donorCanDelete('approved')).toBe(true);
    });

    test('12 - returns true for allocated status', () => {
        expect(donorCanDelete('allocated')).toBe(true);
    });

    test('13 - returns false for received status', () => {
        expect(donorCanDelete('received')).toBe(false);
    });

    test('14 - returns false for delivered status', () => {
        expect(donorCanDelete('delivered')).toBe(false);
    });

    test('15 - returns false for sent status', () => {
        expect(donorCanDelete('sent')).toBe(false);
    });

});

// ─── donorCanChangeCharity ───────────────────────────────────────────────────
describe('donorCanChangeCharity', () => {

    test('16 - returns true for approved status', () => {
        expect(donorCanChangeCharity('approved')).toBe(true);
    });

    test('17 - returns false for unassigned status', () => {
        expect(donorCanChangeCharity('unassigned')).toBe(false);
    });

    test('18 - returns false for assigned status', () => {
        expect(donorCanChangeCharity('assigned')).toBe(false);
    });

    test('19 - returns false for delivered status', () => {
        expect(donorCanChangeCharity('delivered')).toBe(false);
    });

    test('20 - returns false for allocated status', () => {
        expect(donorCanChangeCharity('allocated')).toBe(false);
    });

});

// ─── determineInitialStatus ──────────────────────────────────────────────────
describe('determineInitialStatus', () => {

    test('21 - returns unassigned when no charity provided (null)', () => {
        expect(determineInitialStatus(null)).toEqual({
            status: 'unassigned',
            charity_id: null
        });
    });

    test('22 - returns unassigned for empty string', () => {
        expect(determineInitialStatus('')).toEqual({
            status: 'unassigned',
            charity_id: null
        });
    });

    test('23 - returns unassigned for undefined', () => {
        expect(determineInitialStatus(undefined)).toEqual({
            status: 'unassigned',
            charity_id: null
        });
    });

    test('24 - returns assigned when valid charity id provided', () => {
        expect(determineInitialStatus(3)).toEqual({
            status: 'assigned',
            charity_id: 3
        });
    });

    test('25 - returns assigned when charity id is 1', () => {
        expect(determineInitialStatus(1)).toEqual({
            status: 'assigned',
            charity_id: 1
        });
    });

});

// ─── transitionItem ──────────────────────────────────────────────────────────
describe('transitionItem', () => {

    test('26 - allows valid transition from unassigned to assigned', () => {
        expect(transitionItem('unassigned', 'assigned')).toBe('assigned');
    });

    test('27 - allows valid transition from assigned to rejected', () => {
        expect(transitionItem('assigned', 'rejected')).toBe('rejected');
    });

    test('28 - allows valid transition from approved to allocated', () => {
        expect(transitionItem('approved', 'allocated')).toBe('allocated');
    });

    test('29 - allows valid transition from allocated to received', () => {
        expect(transitionItem('allocated', 'received')).toBe('received');
    });

    test('30 - allows valid transition from received to sent', () => {
        expect(transitionItem('received', 'sent')).toBe('sent');
    });

    test('31 - allows valid transition from sent to delivered', () => {
        expect(transitionItem('sent', 'delivered')).toBe('delivered');
    });

    test('32 - allows valid transition from sent to never_arrived', () => {
        expect(transitionItem('sent', 'never_arrived')).toBe('never_arrived');
    });

    test('33 - throws error on invalid transition from delivered to assigned', () => {
        expect(() => transitionItem('delivered', 'assigned')).toThrow();
    });

    test('34 - throws error on invalid transition from unassigned to delivered', () => {
        expect(() => transitionItem('unassigned', 'delivered')).toThrow();
    });

    test('35 - throws error on invalid transition from received to unassigned', () => {
        expect(() => transitionItem('received', 'unassigned')).toThrow();
    });

    test('36 - throws error on invalid transition from delivered to sent', () => {
        expect(() => transitionItem('delivered', 'sent')).toThrow();
    });

});

// ─── determineStatusAfterEdit ────────────────────────────────────────────────
describe('determineStatusAfterEdit', () => {

    test('37 - returns unassigned when charity removed from assigned item', () => {
        expect(determineStatusAfterEdit('assigned', 'donor', 1, null))
            .toBe('unassigned');
    });

    test('38 - returns unassigned when charity removed from approved item', () => {
        expect(determineStatusAfterEdit('approved', 'donor', 1, null))
            .toBe('unassigned');
    });

    test('39 - returns assigned when charity added to unassigned item', () => {
        expect(determineStatusAfterEdit('unassigned', 'donor', null, 2))
            .toBe('assigned');
    });

    test('40 - returns assigned when rejected item gets new charity', () => {
        expect(determineStatusAfterEdit('rejected', 'donor', null, 3))
            .toBe('assigned');
    });

    test('41 - returns assigned when approved donor changes charity', () => {
        expect(determineStatusAfterEdit('approved', 'donor', 1, 2))
            .toBe('assigned');
    });

    test('42 - returns same status when charity unchanged on approved item', () => {
        expect(determineStatusAfterEdit('approved', 'donor', 1, 1))
            .toBe('approved');
    });

    test('43 - returns unassigned when charity removed from unassigned item', () => {
        expect(determineStatusAfterEdit('unassigned', 'donor', null, null))
            .toBe('unassigned');
    });

});

// ─── charityAdminCanMarkReceived ─────────────────────────────────────────────
describe('charityAdminCanMarkReceived', () => {

    test('44 - returns true for allocated status', () => {
        expect(charityAdminCanMarkReceived('allocated')).toBe(true);
    });

    test('45 - returns false for received status', () => {
        expect(charityAdminCanMarkReceived('received')).toBe(false);
    });

    test('46 - returns false for approved status', () => {
        expect(charityAdminCanMarkReceived('approved')).toBe(false);
    });

    test('47 - returns false for delivered status', () => {
        expect(charityAdminCanMarkReceived('delivered')).toBe(false);
    });

});

// ─── charityAdminCanSend ─────────────────────────────────────────────────────
describe('charityAdminCanSend', () => {

    test('48 - returns true for received status', () => {
        expect(charityAdminCanSend('received')).toBe(true);
    });

    test('49 - returns false for allocated status', () => {
        expect(charityAdminCanSend('allocated')).toBe(false);
    });

    test('50 - returns false for sent status', () => {
        expect(charityAdminCanSend('sent')).toBe(false);
    });

});

// ─── charityAdminCanReturn ───────────────────────────────────────────────────
describe('charityAdminCanReturn', () => {

    test('51 - returns true for received status', () => {
        expect(charityAdminCanReturn('received')).toBe(true);
    });

    test('52 - returns false for sent status', () => {
        expect(charityAdminCanReturn('sent')).toBe(false);
    });

    test('53 - returns false for allocated status', () => {
        expect(charityAdminCanReturn('allocated')).toBe(false);
    });

});

// ─── recipientCanConfirm ─────────────────────────────────────────────────────
describe('recipientCanConfirm', () => {

    test('54 - returns true for sent status', () => {
        expect(recipientCanConfirm('sent')).toBe(true);
    });

    test('55 - returns false for delivered status', () => {
        expect(recipientCanConfirm('delivered')).toBe(false);
    });

    test('56 - returns false for allocated status', () => {
        expect(recipientCanConfirm('allocated')).toBe(false);
    });

});