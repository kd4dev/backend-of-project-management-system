import { differenceInDays, isPast, parseISO } from "date-fns";

export function getDueDateStatus(dueDate: string | undefined) {
  if (!dueDate) return null;

  const due = parseISO(dueDate);
  const today = new Date();
  const daysUntilDue = differenceInDays(due, today);

  if (isPast(due) && daysUntilDue < 0) {
    return {
      status: "overdue" as const,
      daysText: `${Math.abs(daysUntilDue)} day${Math.abs(daysUntilDue) !== 1 ? "s" : ""} overdue`,
      badgeClass: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
      iconColor: "text-red-600 dark:text-red-400",
    };
  } else if (daysUntilDue <= 3 && daysUntilDue >= 0) {
    return {
      status: "due-soon" as const,
      daysText: daysUntilDue === 0 ? "Due today" : `Due in ${daysUntilDue} day${daysUntilDue !== 1 ? "s" : ""}`,
      badgeClass: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
      iconColor: "text-yellow-600 dark:text-yellow-400",
    };
  } else {
    return {
      status: "future" as const,
      daysText: `Due in ${daysUntilDue} days`,
      badgeClass: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
      iconColor: "text-green-600 dark:text-green-400",
    };
  }
}
