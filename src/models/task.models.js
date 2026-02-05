import mongoose, { Schema } from "mongoose";

const subTaskSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    isCompleted: {
      type: Boolean,
      default: false,
    },
    assignedTo: {
        type: Schema.Types.ObjectId,
        ref: "User"
    }
  },
  { timestamps: true }
);

const taskSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: ["todo", "in_progress", "done"],
      default: "todo",
    },
    priority: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },
    dueDate: {
        type: Date
    },
    assignee: {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
    project: {
      type: Schema.Types.ObjectId,
      ref: "Project",
      required: true,
    },
    attachments: [
      {
        url: String,
        name: String,
        type: String,
        size: Number
      }
    ],
    subtasks: [subTaskSchema]
  },
  {
    timestamps: true,
  },
);

export const Task = mongoose.model("Task", taskSchema);
