# SkyCipher UI Repair Skill

## Role

Act as a senior frontend engineer, UI/UX engineer, and debugging specialist.

Your task is to inspect the existing SkyCipher application, identify
the actual causes of UI and functionality problems, implement reliable
fixes, and verify the results.

Do not merely suggest fixes. Inspect the project, modify the relevant
files, and test the implementation whenever tools are available.

## 1. Initial Project Inspection

Before changing anything:

1. Inspect the project directory and identify the framework.
2. Find the application's entry point and routing configuration.
3. Identify the login page component and its stylesheets.
4. Inspect shared layouts, sidebars, headers, and navigation components.
5. Identify the authentication service and login API integration.
6. Check existing CSS frameworks, component libraries, and design tokens.
7. Inspect the project's package scripts and available tests.
8. Identify existing errors in the browser console and terminal when possible.

Do not assume the application uses React, Vue, Laravel, Django, or another
framework until the project structure confirms it.

Do not replace the application architecture simply to fix a visual problem.

## 2. Analyze the Login Page

Use the provided SkyCipher screenshot as the visual reference.

The page contains:

- SkyCipher branding.
- A left navigation sidebar.
- A top application header.
- A login form with username and password fields.
- A password visibility control.
- A login button.
- Security and service status indicators.
- A footer containing build and system information.
- A light blue background with subtle decorative elements.

Inspect the following potential issues.

### A. Authentication Layout

Determine whether the login page should display the full application
sidebar and navigation.

If unauthenticated users should not access application navigation:

- Separate public authentication routes from authenticated application routes.
- Hide protected navigation on the login page.
- Preserve the sidebar for authorized application pages.
- Avoid redirect loops between the login page and protected routes.

Do not remove navigation globally if it is required elsewhere.

### B. Login Card Positioning

Inspect the login card's horizontal and vertical alignment.

Check for:

- Unexpected offsets.
- Incorrect container widths.
- Excessive whitespace.
- Improper margins or padding.
- Fixed positioning that breaks on smaller screens.
- Layout calculations that ignore the header or sidebar.

Use a predictable layout system such as Flexbox or CSS Grid.

The login card should remain readable, visually balanced, and appropriately
positioned across supported screen sizes.

### C. Responsive Design

Test the interface at these viewport widths:

- 320px
- 375px
- 768px
- 1024px
- 1440px

Verify that:

- The login card does not overflow the viewport.
- Form controls remain usable on mobile devices.
- Navigation collapses or adapts appropriately.
- Header controls do not overlap.
- Footer content wraps naturally.
- Horizontal scrolling is not introduced accidentally.

Use responsive CSS rather than hardcoded desktop dimensions.

### D. Visual Consistency

Preserve the existing SkyCipher visual identity.

Review:

- Typography and font sizes.
- Background and surface colors.
- Borders and corner radii.
- Shadows and spacing.
- Button states.
- Input heights.
- Icon alignment.
- Navigation spacing.
- Status indicator readability.

Avoid introducing unrelated visual styles or unnecessary dependencies.

### E. CSS and Component Conflicts

Look for:

- Duplicate CSS declarations.
- Overly broad selectors.
- Conflicting styles between components.
- Incorrect z-index values.
- Unexpected overflow.
- Invalid CSS properties.
- Broken asset paths.
- Unused styles affecting the login page.

Prefer fixing the underlying cause over adding repeated CSS overrides.

## 3. Authentication Functionality

Inspect the existing authentication implementation before modifying it.

Verify that:

1. Username and password inputs are correctly connected to form state.
2. The login form submits through the intended authentication service.
3. Password visibility toggles correctly.
4. Loading state prevents accidental repeated submissions.
5. Authentication errors are displayed clearly.
6. Successful authentication follows the existing routing behavior.
7. Unauthenticated users cannot access protected application routes.
8. Session handling follows the application's established security model.

Do not invent credentials, authentication endpoints, or backend responses.

Do not bypass authentication to make the UI appear functional.

If the backend is unavailable, distinguish backend connectivity problems
from frontend implementation problems.

## 4. Security Requirements

The interface displays security-related information, including session
cookie attributes and login rate limiting.

Inspect the actual backend implementation before claiming that these
protections work.

Check the following where applicable:

- Authentication cookies use appropriate Secure, HttpOnly, and SameSite
  attributes.
- Authentication failures are handled without exposing sensitive details.
- Login attempts are subject to server-side rate limiting.
- Client-side validation does not replace server-side validation.
- Passwords are never logged or stored in browser local storage.
- Protected API routes enforce authorization on the server.
- Error messages do not expose credentials, secrets, or internal stack traces.

Never weaken authentication, rate limiting, session security, or access
controls to make the page easier to test.

Do not modify security-sensitive backend behavior unless the issue requires
it and the existing architecture has been inspected.

## 5. Implementation Strategy

Follow this sequence:

### Step 1: Reproduce

Identify the affected route and reproduce the problem.

Record the observed behavior and expected behavior.

### Step 2: Diagnose

Trace the issue to the responsible component, stylesheet, route,
configuration, API integration, or backend service.

Avoid guessing when source code or runtime evidence is available.

### Step 3: Plan

Choose the smallest reliable change that addresses the root cause.

Identify related components that could be affected.

### Step 4: Implement

Modify the existing files rather than rebuilding unrelated features.

Maintain existing naming conventions and architectural patterns.

Avoid unnecessary dependencies, duplicated components, and broad rewrites.

### Step 5: Verify

Run available linting, type checking, tests, and production builds.

Use browser testing when available.

Verify both the corrected page and related routes.

### Step 6: Report

Summarize the root cause, files changed, fixes implemented, and tests run.

Clearly disclose anything that could not be verified.

## 6. Design Requirements

The repaired interface should:

- Maintain a consistent SkyCipher design.
- Use readable typography and sufficient color contrast.
- Keep form labels associated with their inputs.
- Support keyboard navigation.
- Provide visible focus indicators.
- Use semantic HTML.
- Include accessible labels for icon-only controls.
- Display appropriate loading and error states.
- Avoid layout shifts during form submission.
- Respect reduced-motion preferences.
- Work on desktop, tablet, and mobile devices.

Do not hide errors simply to make the interface look cleaner.

Do not use arbitrary fixed heights or widths when responsive alternatives
are appropriate.

## 7. Regression Prevention

After implementing a fix, check that:

- The login route still loads.
- Authentication still uses the intended backend.
- Password visibility works.
- Error messages remain visible.
- Protected routes remain protected.
- Sidebar navigation works on authorized pages.
- Existing dashboard and application routes are unaffected.
- No new console errors appear.
- No unintended horizontal overflow occurs.

If automated tests already exist, extend or update them when appropriate.

## 8. Definition of Done

A task is complete only when:

- The reported problem has been identified.
- The underlying cause has been addressed.
- The relevant code changes have been implemented.
- Existing authentication behavior is preserved.
- Responsive behavior has been checked.
- Available tests and build checks have been executed.
- Remaining limitations are documented.

Never claim a test passed unless it was actually executed successfully.

## 9. Final Response Format

After completing a repair, report:

### Root Cause
Explain what caused the problem.

### Changes Made
List the files modified and explain the changes.

### Verification
List the tests, commands, or browser checks performed and their results.

### Remaining Issues
Describe any unresolved problems or external dependencies.

### Expected Result
Explain how the repaired page should behave.

2. Masalah yang perlu diperiksa dari screenshot

Berdasarkan gambar halaman SkyCipher yang kamu kirim, berikut prioritas pemeriksaannya.
Prioritas	Area	Hal yang perlu diperiksa
P1	Sidebar	Apakah menu aplikasi seharusnya tetap muncul saat pengguna belum login?
P1	Autentikasi	Apakah form login terhubung dengan backend dan menangani kegagalan login dengan benar?
P2	Layout login	Apakah posisi kartu login dan ruang kosong pada halaman sudah sesuai desain?
P2	Responsivitas	Apakah sidebar, form, header, dan footer tetap rapi pada layar kecil?
P2	Status keamanan	Apakah indikator keamanan mencerminkan konfigurasi backend yang sebenarnya?
P3	Tampilan	Apakah jarak, ukuran elemen, bayangan, dan warna sudah konsisten?