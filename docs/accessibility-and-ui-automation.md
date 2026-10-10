# Windows Accessibility and UI Automation (UIA) for AI Agents and Users

This document outlines the accessibility and UI automation architecture of RefineID on Windows. It explains how Windows Accessibility standards and the UI Automation (UIA) framework serve a dual purpose: providing assistive technology for human users (e.g. screen readers like Windows Narrator) and providing deterministic, semantic assistive technology for autonomous AI agents.

---

## 1. The Dual Purpose of UI Accessibility

Visual desktop interaction designed solely for human sight and physical mouse pointers presents severe barriers to two distinct groups:
1. **Human users with visual or motor impairments**, who rely on assistive technologies (screen readers, braille displays, keyboard navigation, and switch access).
2. **Autonomous AI agents**, which do not possess human optical vision or physical hands. When agents rely exclusively on pixel screenshots, computer vision, and optical character recognition (OCR), interactions are brittle, slow, prone to screen resolution/scaling artifacts, and lack semantic understanding of control state.

By implementing first-class Windows Accessibility standards across our WinUI 3 applications, we achieve **universal accessibility**: the application is fully operable by human assistive tools and deterministically inspectable and controllable by autonomous AI agents.

---

## 2. UI Automation (UIA) Architecture

Windows UI Automation (`IUIAutomation` in Win32, `System.Windows.Automation` in .NET) exposes a hierarchical, semantic control tree directly to client applications:

```text
                     Desktop Root (AutomationElement)
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
         Browser Window (Firefox)           RefineID WinUI 3 Window
                  │                                   │
       ┌──────────┴──────────┐             ┌──────────┴──────────┐
       ▼                     ▼             ▼                     ▼
 [password1Textbox]    [reload-button]  [VerifyCard]       [ReaderComboBox]
 - AutomationId        - AutomationId   - AutomationId     - AutomationId
 - ControlType.Edit    - ControlType.   - ControlType.     - ControlType.
 - HasKeyboardFocus        Button           Button             ComboBox
 - SetFocus()          - Invoke()       - Invoke()         - SelectionPattern
```

### Key Capabilities for Agents and Assistive Tech:
- **Deterministic Targeting**: Finding elements by stable `AutomationId` (`AutomationElement.AutomationIdProperty`) rather than coordinate heuristics.
- **Control Patterns**: Calling semantic actions directly via UIA patterns:
  - `InvokePattern`: Trigger buttons, links, and actionable cards without mouse cursor positioning.
  - `ValuePattern`: Read and set editable text contents safely.
  - `SelectionPattern`: Enumerate and select items in combo boxes and lists.
- **State & Focus Inspection**: Querying `HasKeyboardFocus`, `IsEnabled`, `IsPassword`, and `ItemStatus` before taking action.

---

## 3. WinUI 3 Accessibility Implementation

All user-facing XAML views in RefineID (`apps/RefineID-winui`) implement comprehensive UIA attributes:

### A. Semantic Heading Structure
Headings guide screen reader users and AI agents through logical document hierarchy:
```xml
<TextBlock
    Text="Card management"
    Style="{StaticResource BodyStrongTextBlockStyle}"
    AutomationProperties.HeadingLevel="Level2" />
```

### B. Actionable Cards and Buttons
Interactive cards and buttons expose explicit names, automation IDs, and descriptive help text:
```xml
<controls:SettingsCard
    x:Name="VerifyCard"
    Header="Verify"
    IsClickEnabled="True"
    AutomationProperties.AutomationId="VerifyCard"
    AutomationProperties.Name="Verify document"
    AutomationProperties.HelpText="Verify a signed document using the card" />
```

### C. Input Controls and Dialogs
All text inputs, password boxes, and combo boxes specify explicit accessible names:
```xml
<PasswordBox
    x:Name="CurrentPinBox"
    Header="Current PIN"
    MaxLength="12"
    PasswordRevealMode="Peek"
    AutomationProperties.AutomationId="CurrentPinBox"
    AutomationProperties.Name="Current PIN" />
```

### D. Progress and Status Indicators
Asynchronous operations announce their status semantically:
```xml
<ProgressRing
    x:Name="BusyRing"
    IsActive="True"
    AutomationProperties.AutomationId="BusyRing"
    AutomationProperties.Name="Working with the card" />
```

---

## 4. Hardware-Level Input with `prlkey`

When running inside virtualized test environments (such as Parallels Desktop on ARM64 hosts), agents can combine UIA semantic inspection with hypervisor-level input injection using `prlkey`:

- **Hypervisor Injection**: `prlctl send-key-event "$VM_NAME" -j` transmits raw hardware scan codes directly into the virtual machine's virtual keyboard controller.
- **Bypassing OS UIPI & Focus Stealing**: Keystrokes are processed at the hardware driver level, eliminating session boundary and UIPI (User Interface Privilege Isolation) restrictions.
- **Workflow**:
  1. The agent uses UIA to locate and focus the target control (e.g. `password1Textbox.SetFocus()`).
  2. The agent sends keystrokes via `prlkey <tokens>` (e.g. `prlkey <digits> ENTER`).
  3. The agent monitors state changes via UIA events or re-polling.
