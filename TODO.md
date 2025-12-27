# TODO: Alumni Portal Enhancement

## Task Overview
Enhance the alumni portal to:
1. Add alumni number generation and display in admin users section
2. Extend signup loading time to 9 seconds

## Plan Details

### 1. Database Schema Updates
- [ ] Add `alumni_number` column to users table with unique constraint
- [ ] Generate random alumni number for existing users (migration script)

### 2. Backend Changes (app.py)
- [ ] Modify signup() function to generate and store random alumni number
- [ ] Add alumni_number to user profile retrieval queries
- [ ] Ensure alumni_number is included in session data

### 3. Admin Dashboard Updates (admin_dashboard.html)
- [ ] Update users section to display alumni_number and graduation_year columns
- [ ] Add proper table headers and data population

### 4. Student Dashboard Updates (student_dashboard.html)
- [ ] Add display of user's alumni_number in profile section
- [ ] Show graduation year prominently

### 5. Frontend Updates (signup.html)
- [ ] Increase loading time from 1.4 seconds to 9 seconds
- [ ] Ensure loading message remains "Connecting to school database..."

### 6. Testing
- [ ] Test signup flow with new alumni number generation
- [ ] Verify admin can see alumni numbers in users section
- [ ] Confirm 9-second loading time works correctly
- [ ] Test existing user data migration

## Technical Implementation Notes

### Alumni Number Format
- Random 8-digit number (e.g., "20240001")
- Should be unique and easy to remember
- Store as TEXT to handle leading zeros if needed

### Database Migration
- Add alumni_number column with unique constraint
- Generate alumni numbers for existing users
- Make alumni_number required for new signups

### Loading Time Enhancement
- Current: 1400ms (1.4 seconds)
- Target: 9000ms (9 seconds)
- Maintain same visual feedback and user experience
