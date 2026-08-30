import { useState } from "react";
import "./ProjectCreate.css";

function ProjectCreate({
  onBack,
  onCreate,
  currentUser,
}) {
  const [name, setName] =
    useState("");

  const [description, setDescription] =
    useState("");

  const [error, setError] =
    useState("");


  const handleSubmit = (event) => {
    event.preventDefault();

    const trimmedName =
      name.trim();

    const trimmedDescription =
      description.trim();

    if (!trimmedName) {
      setError("프로젝트명을 입력해주세요.");
      return;
    }

    setError("");

    const newProject = {
      id: Date.now(),
      name: trimmedName,
      description: trimmedDescription,
      createdBy:
        currentUser?.username || "admin",
      createdAt:
        new Date().toLocaleString("ko-KR"),
      currentSourceVersion: null,
      analysisHistories: [],
      assignedUsers: [],
    };

    onCreate(newProject);
  };


  return (
    <div className="project-create">

      <div className="project-create-header">
        <button
          type="button"
          className="back-button"
          onClick={onBack}
        >
          ← 목록으로
        </button>

        <div className="project-create-title">
          <h1>프로젝트 등록</h1>
          <p>
            새로운 분석 프로젝트의 기본 정보를 등록합니다.
          </p>
        </div>
      </div>


      <form
        className="project-create-form"
        onSubmit={handleSubmit}
      >
        {error && (
          <div className="project-create-error">
            {error}
          </div>
        )}

        <div className="form-group">
          <label htmlFor="project-name">
            프로젝트명
            <span className="required">*</span>
          </label>

          <input
            id="project-name"
            type="text"
            value={name}
            onChange={(event) =>
              setName(event.target.value)
            }
            placeholder="프로젝트명을 입력해주세요."
          />
        </div>

        <div className="form-group">
          <label htmlFor="project-description">
            설명
          </label>

          <textarea
            id="project-description"
            value={description}
            onChange={(event) =>
              setDescription(
                event.target.value
              )
            }
            placeholder="프로젝트에 대한 설명을 입력해주세요."
          />
        </div>

        <div className="project-create-actions">
          <button
            type="button"
            className="cancel-button"
            onClick={onBack}
          >
            취소
          </button>

          <button
            type="submit"
            className="submit-button"
          >
            등록
          </button>
        </div>
      </form>

    </div>
  );
}

export default ProjectCreate;